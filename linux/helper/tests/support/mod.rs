/* Shared guards for the fixed-path helper integration tests.
 *
 * Both test executables create `/opt/hotspotshade` and
 * `/var/lib/hotspotshade`, so they must not run at the same time. One
 * cross-process `flock` covers both executables, and one in-process mutex
 * covers the test threads inside an executable.
 *
 * Cleanup checks the device, inode, and owner of every directory and requires
 * that no engine process is alive. The final removal is not atomic with the
 * identity check; a same-user replacement can race it. A failed or uncertain check leaves the trees in place and
 * reports a residual failure.
 *
 * The process-group guard never reaps its leader before it has stopped the
 * rest of the group. It signals a group only while the leader is unreaped and
 * its process id and start time still match the spawned process.
 *
 * `wait_exit` fails when a live group member survives its leader. The guard
 * still cleans that orphan and reaps the leader first, so the failure leaves
 * nothing behind. Every wait is bounded, including the reap after SIGKILL: a
 * leader that SIGKILL cannot end is reported as a residual and abandoned.
 *
 * TEST-ONLY SIGKILL FALLBACK: after a graceful `SIGTERM` window the group
 * guard sends `SIGKILL` to the verified group. That is safe here because these
 * tests start no tunnel and create no route or TUN device, so there is no
 * kernel cleanup path to skip. Do not copy that fallback into the helper or
 * any path that can own a tunnel.
 */
#![allow(dead_code)]

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const ENGINE_ROOT: &str = "/opt/hotspotshade";
pub const ENGINE_RESOURCES: &str = "/opt/hotspotshade/resources";
pub const ENGINE_DIR: &str = "/opt/hotspotshade/resources/engine";
pub const ENGINE: &str = "/opt/hotspotshade/resources/engine/hotspotshade";
pub const HOME_DIR: &str = "/var/lib/hotspotshade";
pub const STATE: &str = "/var/lib/hotspotshade/engine.state";

/* The lock lives beside the fixed home, not inside it, so removing the home
 * cannot replace the inode that another test executable is waiting on. */
const TEST_LOCK: &str = "/var/lib/hotspotshade-helper-tests.lock";

const LOCK_WAIT: Duration = Duration::from_secs(180);
const GROUP_GRACE: Duration = Duration::from_secs(70);
const GROUP_KILL_GRACE: Duration = Duration::from_secs(5);

static FIXED_PATHS: Mutex<()> = Mutex::new(());
static PROCESS_LOCK: OnceLock<File> = OnceLock::new();

fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

pub fn root() -> bool {
    fs::read_to_string("/proc/self/status")
        .map(|text| text.lines().any(|line| line == "Uid:\t0\t0\t0\t0"))
        .unwrap_or(false)
}

pub fn in_container() -> bool {
    Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists()
}

pub fn enabled() -> bool {
    if env::var("HS_HELPER_INTEGRATION").ok().as_deref() != Some("1") {
        return false;
    }
    assert!(
        root() && in_container(),
        "integration tests require root in a disposable container"
    );
    eprintln!(
        "HS_HELPER_TEST_STARTED {}",
        thread::current().name().expect("test thread name")
    );
    true
}

/* One test at a time. The returned guard holds the in-process mutex. The
 * cross-process file lock stays held for the rest of this executable's life,
 * so the second test executable waits until the first exits. */
pub struct Reservation {
    _guard: MutexGuard<'static, ()>,
}

pub fn reserve() -> Reservation {
    let guard = FIXED_PATHS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    check_fixed_parents().unwrap_or_else(|error| {
        panic!("refusing the fixed-path test reservation: {error}");
    });
    PROCESS_LOCK.get_or_init(|| {
        acquire_lock_at(Path::new(TEST_LOCK), effective_uid(), LOCK_WAIT)
            .unwrap_or_else(|error| panic!("the fixed-path test lock is not safe to use: {error}"))
    });
    Reservation { _guard: guard }
}

/* Fail closed on an existing lock that another user could replace. The open
 * uses O_NOFOLLOW, and the descriptor metadata is checked after the open. */
pub fn acquire_lock_at(path: &Path, expected_uid: u32, wait: Duration) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the lock is not a private file owned by the test user",
        ));
    }
    let deadline = Instant::now() + wait;
    loop {
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            let current = fs::symlink_metadata(path)?;
            let opened = file.metadata()?;
            if !current.is_file()
                || current.dev() != opened.dev()
                || current.ino() != opened.ino()
                || opened.nlink() != 1
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "lock path changed while acquiring lock",
                ));
            }
            return Ok(file);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(error);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "another helper test executable holds the fixed-path lock",
            ));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/* /opt and /var/lib must be real root-owned directories on the disposable
 * container root filesystem. A host bind mount or a separate volume can
 * outlive the container, and the test must not write into it. */
pub fn check_fixed_parents() -> Result<(), String> {
    for path in [
        Path::new("/"),
        Path::new("/opt"),
        Path::new("/var"),
        Path::new("/var/lib"),
    ] {
        check_parent_dir(path)?;
    }
    Ok(())
}

fn check_parent_dir(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("read the parent {}: {error}", path.display()))?;
    if !metadata.is_dir() {
        return Err(format!(
            "the parent {} must be a real directory, not a symlink",
            path.display()
        ));
    }
    if metadata.uid() != 0 {
        return Err(format!(
            "the parent {} must be owned by root, not uid {}",
            path.display(),
            metadata.uid()
        ));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(format!(
            "the parent {} must not be writable by another user",
            path.display()
        ));
    }
    if path != Path::new("/") {
        let root_metadata =
            fs::symlink_metadata("/").map_err(|error| format!("read the root: {error}"))?;
        if metadata.dev() != root_metadata.dev() {
            return Err(format!(
                "the parent {} is on another device; refusing a host bind mount or volume",
                path.display()
            ));
        }
        if is_mount_point(path)? {
            return Err(format!(
                "the parent {} is a mount point; refusing a host bind mount or volume that can outlive the container",
                path.display()
            ));
        }
    }
    Ok(())
}

fn is_mount_point(path: &Path) -> Result<bool, String> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")
        .map_err(|error| format!("read the mount table: {error}"))?;
    let target = path.to_string_lossy();
    for line in mountinfo.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 {
            return Err("invalid mount table entry".to_owned());
        }
        if unescape_mount_path(fields[4]) == target {
            return Ok(true);
        }
    }
    Ok(false)
}

fn unescape_mount_path(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirIdentity {
    pub dev: u64,
    pub ino: u64,
    pub uid: u32,
}

impl DirIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            uid: metadata.uid(),
        }
    }

    fn matches(&self, metadata: &fs::Metadata) -> bool {
        metadata.is_dir()
            && metadata.dev() == self.dev
            && metadata.ino() == self.ino
            && metadata.uid() == self.uid
    }
}

/* A directory this test created, or adopted from a sentinel, with the identity
 * used to check the directory before removal. */
pub struct OwnedDir {
    path: PathBuf,
    identity: DirIdentity,
    cleaned: bool,
}

impl OwnedDir {
    pub fn create(path: &Path, mode: u32) -> io::Result<Self> {
        let mut builder = fs::DirBuilder::new();
        builder.mode(mode);
        builder.create(path)?;
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "cannot identify newly created {}; residual: {error}",
                    path.display()
                ),
            )
        })?;
        let mut owned = Self {
            path: path.to_path_buf(),
            identity: DirIdentity::from_metadata(&metadata),
            cleaned: false,
        };
        let result = (|| {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)?;
            if !owned.identity.matches(&file.metadata()?) || metadata.uid() != effective_uid() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "new directory identity is uncertain",
                ));
            }
            file.set_permissions(fs::Permissions::from_mode(mode))?;
            owned.verify().map_err(io::Error::other)?;
            if file.metadata()?.mode() & 0o777 != mode {
                return Err(io::Error::other("directory mode mismatch"));
            }
            Ok(())
        })();
        if let Err(error) = result {
            return match owned.cleanup() {
                Ok(()) => Err(error),
                Err(residual) => Err(io::Error::new(
                    error.kind(),
                    format!("{error}; rollback residual: {}", residual.join("; ")),
                )),
            };
        }
        Ok(owned)
    }

    pub fn adopt(path: &Path, mode: u32) -> io::Result<Self> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir() || metadata.uid() != effective_uid() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the test directory is not a directory owned by the test user",
            ));
        }
        if metadata.mode() & 0o777 != mode {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the test directory does not have the expected mode",
            ));
        }
        Ok(Self {
            path: path.to_path_buf(),
            identity: DirIdentity::from_metadata(&metadata),
            cleaned: false,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn identity(&self) -> DirIdentity {
        self.identity
    }

    /* Stop owning a path whose identity was moved outside this guard. The
     * caller is then responsible for the tree. */
    pub fn forget(&mut self) {
        self.cleaned = true;
    }

    pub fn verify(&self) -> Result<(), String> {
        let metadata = fs::symlink_metadata(&self.path)
            .map_err(|error| format!("read {} before cleanup: {error}", self.path.display()))?;
        if !self.identity.matches(&metadata) {
            return Err(format!(
                "{} no longer has the device, inode, and owner it was created with; refusing to remove it",
                self.path.display()
            ));
        }
        Ok(())
    }

    pub fn cleanup(&mut self) -> Result<(), Vec<String>> {
        if self.cleaned {
            return Ok(());
        }
        self.cleaned = true;
        if let Err(error) = self.verify() {
            return Err(vec![error]);
        }
        remove_owned_tree(&self.path, self.identity).map_err(|error| {
            vec![format!(
                "remove the tested directory {}: {error}",
                self.path.display()
            )]
        })
    }
}

impl Drop for OwnedDir {
    fn drop(&mut self) {
        if self.cleaned {
            return;
        }
        if let Err(errors) = self.cleanup() {
            for error in errors {
                eprintln!("hotspotshade helper test cleanup: {error}");
            }
        }
    }
}

/* Remove the contents through an opened descriptor, then recheck the path
 * identity before removing the directory itself. Anchoring the parent avoids
 * following a replaced ancestor, but a replacement between the final check
 * and remove can still be removed. */
fn remove_owned_tree(path: &Path, identity: DirIdentity) -> io::Result<()> {
    let mounts = fs::read_to_string("/proc/self/mountinfo")?;
    let prefix = format!("{}/", path.display());
    for line in mounts.lines() {
        let target = line
            .split_whitespace()
            .nth(4)
            .ok_or_else(|| io::Error::other("invalid mount table"))?;
        let target = unescape_mount_path(target);
        if target == path.to_string_lossy() || target.starts_with(&prefix) {
            return Err(io::Error::other(
                "mount under owned directory; refusing cleanup",
            ));
        }
    }
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("missing parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::other("missing directory name"))?;
    let parent_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)?;
    let anchored_path =
        PathBuf::from(format!("/proc/self/fd/{}", parent_file.as_raw_fd())).join(name);
    let metadata = fs::symlink_metadata(&anchored_path)?;
    if !identity.matches(&metadata) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the directory identity changed; refusing to remove it",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&anchored_path)?;
    if !identity.matches(&file.metadata()?) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the opened directory identity changed; refusing to remove it",
        ));
    }
    let descriptor_path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
    remove_directory_contents(&descriptor_path)?;
    let after = fs::symlink_metadata(&anchored_path)?;
    if !identity.matches(&after) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the directory identity changed during cleanup; refusing the final remove",
        ));
    }
    fs::remove_dir(&anchored_path)
}

fn remove_directory_contents(path: &Path) -> io::Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let entry_path = entry.path();
        if file_type.is_dir() {
            fs::remove_dir_all(&entry_path)?;
        } else {
            fs::remove_file(&entry_path)?;
        }
    }
    Ok(())
}

/* The fixed test roots in creation order. Each is created exclusively, so a
 * pre-existing path, a symlink, or a mount point at one of them is refused and
 * never adopted. `mkdir` is not recursive, so every parent is listed. */
const SANDBOX_LAYOUT: [(&str, u32); 4] = [
    (ENGINE_ROOT, 0o755),
    (ENGINE_RESOURCES, 0o755),
    (ENGINE_DIR, 0o755),
    (HOME_DIR, 0o700),
];

pub struct Sandbox {
    dirs: Vec<OwnedDir>,
}

impl Sandbox {
    pub fn create() -> Result<Self, String> {
        check_fixed_parents()?;
        let mut sandbox = Self { dirs: Vec::new() };
        for (path, mode) in SANDBOX_LAYOUT {
            match OwnedDir::create(Path::new(path), mode) {
                Ok(directory) => sandbox.dirs.push(directory),
                Err(error) => {
                    if error.to_string().contains("residual:") {
                        for directory in &mut sandbox.dirs {
                            directory.forget();
                        }
                        return Err(format!(
                            "create {path}: {error}; keeping ancestors for inspection"
                        ));
                    }
                    /* Roll back only what this call created. The path that
                     * failed is not ours and is never touched. */
                    let suffix = match sandbox.cleanup() {
                        Ok(()) => String::new(),
                        Err(errors) => {
                            format!("; the rollback also failed: {}", errors.join("; "))
                        }
                    };
                    return Err(format!("create {path} exclusively: {error}{suffix}"));
                }
            }
        }
        Ok(sandbox)
    }

    pub fn engine_root(&self) -> &Path {
        Path::new(ENGINE_ROOT)
    }

    pub fn engine_dir(&self) -> &Path {
        Path::new(ENGINE_DIR)
    }

    pub fn home(&self) -> &Path {
        Path::new(HOME_DIR)
    }

    pub fn verify(&self) -> Result<(), Vec<String>> {
        let errors: Vec<String> = self
            .dirs
            .iter()
            .filter_map(|directory| directory.verify().err())
            .collect();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /* Remove the trees only after proving that no engine is alive and that
     * every directory still has its recorded identity. A refusal keeps every
     * tree in place and reports why. The caller then owns the leftovers. */
    pub fn cleanup(&mut self) -> Result<(), Vec<String>> {
        if self.dirs.is_empty() {
            return Ok(());
        }
        match engine_alive() {
            Ok(false) => {}
            Ok(true) => {
                return Err(vec![
                    "an engine process is still alive; keeping the test roots".to_owned(),
                ]);
            }
            Err(error) => {
                return Err(vec![format!(
                    "cannot prove that no engine is alive ({error}); keeping the test roots"
                )]);
            }
        }
        self.verify()?;
        let mut errors = Vec::new();
        let mut blocked = false;
        /* Children first. After one failure, keep every remaining ancestor:
         * a removal below would otherwise delete a tree that was swapped in. */
        while let Some(mut directory) = self.dirs.pop() {
            if blocked {
                directory.cleaned = true;
                errors.push(format!(
                    "kept {} because a directory below it was not removed",
                    directory.path().display()
                ));
                continue;
            }
            if let Err(mut failure) = directory.cleanup() {
                errors.append(&mut failure);
                blocked = true;
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        if let Err(errors) = self.cleanup() {
            for error in errors {
                eprintln!("hotspotshade helper test cleanup: {error}");
            }
        }
        /* A refused cleanup left directories here. Their own drop would remove
         * them without the engine check, so disarm them. */
        for directory in &mut self.dirs {
            directory.cleaned = true;
        }
    }
}

pub fn private_temp_dir(label: &str) -> io::Result<OwnedDir> {
    let base = PathBuf::from("/var/lib");
    check_parent_dir(&base).map_err(io::Error::other)?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or(0);
    for attempt in 0..100u128 {
        let path = base.join(format!(
            "hotspotshade-test-{label}-{}-{}",
            std::process::id(),
            nanos + attempt
        ));
        match OwnedDir::create(&path, 0o700) {
            Ok(directory) => return Ok(directory),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "no private test directory name was available",
    ))
}

/* Read the start time field of /proc/<pid>/stat. It does not prove ownership,
 * but with an unreaped process id it identifies the same process across a
 * signal decision. */
pub fn process_start_time(pid: u32) -> Option<u64> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = text.rfind(')')?;
    text.get(close + 1..)?
        .split_whitespace()
        .nth(19)?
        .parse::<u64>()
        .ok()
}

fn process_state(pid: u32) -> Option<char> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = text.rfind(')')?;
    text.get(close + 1..)?
        .split_whitespace()
        .next()?
        .chars()
        .next()
}

fn process_group(pid: u32) -> Option<u32> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = text.rfind(')')?;
    text.get(close + 1..)?
        .split_whitespace()
        .nth(2)?
        .parse::<u32>()
        .ok()
}

/* Return true only when the state record names a live process, or when the
 * process table names an executable under the test engine root. A pending
 * record and an uncertain read are errors so the caller keeps the roots. */
pub fn engine_alive() -> Result<bool, String> {
    let lock_path = Path::new(HOME_DIR).join("helper.lock");
    match OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&lock_path)
    {
        Ok(file) => {
            let metadata = file
                .metadata()
                .map_err(|error| format!("inspect helper lock: {error}"))?;
            if !metadata.is_file()
                || metadata.uid() != effective_uid()
                || metadata.mode() & 0o077 != 0
                || metadata.nlink() != 1
            {
                return Err("unsafe helper lock".to_owned());
            }
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                if io::Error::last_os_error().raw_os_error() == Some(libc::EWOULDBLOCK) {
                    return Ok(true);
                }
                return Err(format!(
                    "helper lock is held or unreadable: {}",
                    io::Error::last_os_error()
                ));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("open helper lock: {error}")),
    }
    match fs::symlink_metadata(STATE) {
        Ok(metadata) => {
            if !metadata.is_file()
                || metadata.uid() != effective_uid()
                || metadata.mode() & 0o077 != 0
            {
                return Err("the engine state record is not a private file".to_owned());
            }
            let text = fs::read_to_string(STATE)
                .map_err(|error| format!("read the engine state record: {error}"))?;
            match parse_state(&text) {
                Some(TestState::Engine { pid, start_time }) => {
                    match fs::read_to_string(format!("/proc/{pid}/stat")) {
                        Ok(text) => {
                            if !recorded_process_exited(&text, start_time)? {
                                return Ok(true);
                            }
                        }
                        Err(error) if disappeared(&error) => {}
                        Err(error) => {
                            return Err(format!("cannot inspect recorded engine: {error}"));
                        }
                    }
                }
                Some(TestState::Pending) => {
                    return Err("a pending engine start is recorded".to_owned());
                }
                None => return Err("the engine state record is malformed".to_owned()),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("read the engine state record: {error}")),
    }
    engine_process_alive()
}

/* Scan /proc only. This is for tests that must prove an engine process is gone
 * while a pending state record deliberately remains. */
pub fn engine_process_alive() -> Result<bool, String> {
    let entries =
        fs::read_dir("/proc").map_err(|error| format!("read the process table: {error}"))?;
    let root = ENGINE_ROOT.as_bytes();
    for entry in entries {
        let entry = entry.map_err(|error| format!("read process entry: {error}"))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let cmdline = match fs::read(entry.path().join("cmdline")) {
            Ok(value) => value,
            Err(error) if disappeared(&error) => continue,
            Err(error) => return Err(format!("read process command line: {error}")),
        };
        let found = cmdline.split(|byte| *byte == 0).any(|argument| {
            argument == root
                || (argument.starts_with(root) && argument.get(root.len()) == Some(&b'/'))
                || argument.rsplit(|byte| *byte == b'/').next() == Some(b"hotspotshade-helper")
        });
        if found {
            return Ok(true);
        }
    }
    Ok(false)
}

enum TestState {
    Engine { pid: u32, start_time: u64 },
    Pending,
}

fn parse_state(text: &str) -> Option<TestState> {
    let mut lines = text.lines();
    if lines.next()? != "HS_ENGINE 2" {
        return None;
    }
    let boot = lines.next()?.strip_prefix("BOOT ")?;
    if boot.len() != 36 {
        return None;
    }
    let mut ns = lines.next()?.strip_prefix("NS ")?.split_whitespace();
    ns.next()?.parse::<u64>().ok()?;
    ns.next()?.parse::<u64>().ok()?;
    if ns.next().is_some() {
        return None;
    }
    let mut parts = lines.next()?.split_whitespace();
    let kind = parts.next()?;
    let pid = parts.next()?.parse::<u32>().ok()?;
    let start_time = parts.next()?.parse::<u64>().ok()?;
    if pid == 0 || start_time == 0 || parts.next().is_some() || lines.next().is_some() {
        return None;
    }
    match kind {
        "ENGINE" => Some(TestState::Engine { pid, start_time }),
        "PENDING" => Some(TestState::Pending),
        _ => None,
    }
}

pub fn boot_id() -> Option<String> {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|value| value.trim().to_owned())
}

pub fn pid_namespace() -> Option<(u64, u64)> {
    let metadata = fs::metadata("/proc/self/ns/pid").ok()?;
    Some((metadata.dev(), metadata.ino()))
}

pub fn engine_state_text(pid: u32, start_time: u64) -> String {
    let boot = boot_id().expect("read the kernel boot id");
    let (dev, ino) = pid_namespace().expect("read this PID namespace");
    format!("HS_ENGINE 2\nBOOT {boot}\nNS {dev} {ino}\nENGINE {pid} {start_time}\n")
}

pub fn pending_state_text(pid: u32, start_time: u64) -> String {
    let boot = boot_id().expect("read the kernel boot id");
    let (dev, ino) = pid_namespace().expect("read this PID namespace");
    format!("HS_ENGINE 2\nBOOT {boot}\nNS {dev} {ino}\nPENDING {pid} {start_time}\n")
}

fn is_dead_state(state: Option<char>) -> bool {
    matches!(state, Some('Z') | Some('X') | Some('x'))
}

/* True when the process is gone, replaced by another process under the same
 * id, or a zombie that its parent has not reaped. A zombie cannot run, so a
 * frozen parent that never reaps it does not make it alive. */
fn disappeared(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH))
}

pub fn process_exited(pid: u32, start_time: u64) -> Result<bool, String> {
    process_exited_from_read(
        pid,
        start_time,
        fs::read_to_string(format!("/proc/{pid}/stat")),
    )
}

fn process_exited_from_read(
    pid: u32,
    start_time: u64,
    result: io::Result<String>,
) -> Result<bool, String> {
    match result {
        Err(error) if disappeared(&error) => Ok(true),
        Err(error) => Err(format!("read process {pid}: {error}")),
        Ok(text) => recorded_process_exited(&text, start_time),
    }
}

fn recorded_process_exited(text: &str, start_time: u64) -> Result<bool, String> {
    let fields: Vec<_> = text
        .rsplit_once(')')
        .ok_or("invalid process stat")?
        .1
        .split_whitespace()
        .collect();
    let start = fields
        .get(19)
        .ok_or("missing process start time")?
        .parse::<u64>()
        .map_err(|error| error.to_string())?;
    let raw_state = *fields.first().ok_or("missing process state")?;
    if raw_state.len() != 1 || !"RSDZTtXxKWPI".contains(raw_state) {
        return Err("invalid process state".to_owned());
    }
    let state = raw_state.chars().next().ok_or("empty process state")?;
    Ok(start != start_time || is_dead_state(Some(state)))
}

#[test]
fn recorded_zombie_is_dead_but_invalid_stat_is_uncertain() {
    if !enabled() {
        return;
    }
    for code in [libc::ENOENT, libc::ESRCH] {
        assert_eq!(
            process_exited_from_read(123, 42, Err(io::Error::from_raw_os_error(code))),
            Ok(true)
        );
        assert!(disappeared(&io::Error::from_raw_os_error(code)));
    }
    assert!(
        process_exited_from_read(123, 42, Err(io::Error::from_raw_os_error(libc::EACCES))).is_err()
    );
    assert!(!disappeared(&io::Error::from_raw_os_error(libc::EACCES)));
    let stat = format!("123 (engine) Z {} 42", vec!["0"; 18].join(" "));
    assert_eq!(recorded_process_exited(&stat, 42), Ok(true));
    let live = stat.replace(") Z ", ") S ");
    assert_eq!(recorded_process_exited(&live, 42), Ok(false));
    assert!(recorded_process_exited("bad", 42).is_err());
    assert!(recorded_process_exited(&stat.replace(") Z ", ") Zombie "), 42).is_err());
}

/* The `socket:[inode]` descriptor targets that a process holds. */
pub fn socket_descriptors(pid: u32) -> io::Result<Vec<String>> {
    let mut found = Vec::new();
    for entry in fs::read_dir(format!("/proc/{pid}/fd"))? {
        let entry = entry?;
        let target = match fs::read_link(entry.path()) {
            Ok(target) => target,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let text = target.to_string_lossy().into_owned();
        if text.starts_with("socket:[") {
            found.push(text);
        }
    }
    found.sort();
    Ok(found)
}

#[derive(Debug)]
pub struct GroupStop {
    pub status: Option<ExitStatus>,
    pub forced: bool,
    pub residual: bool,
    /* The leader had already exited, but a live group member survived it. */
    pub orphaned: bool,
}

/* A spawned process group. The caller must set `process_group(0)` before the
 * spawn, so the group id equals the child process id. */
pub struct ProcessGroup {
    child: Option<Child>,
    pid: u32,
    start_time: u64,
    reaped: bool,
    /* The leader could not be reaped within the bounded wait after the forced
     * kill. The guard gives up instead of blocking, and reports a residual. */
    abandoned: bool,
    status: Option<ExitStatus>,
    failure: Option<String>,
}

impl ProcessGroup {
    pub fn new(child: Child) -> io::Result<Self> {
        let pid = child.id();
        let Some(start_time) = process_start_time(pid) else {
            let mut child = child;
            // An unreaped child PID cannot be reused. Only signal the group
            // when the kernel still identifies this child as its leader.
            if process_group(pid) == Some(pid) {
                let _ = signal_group(pid, libc::SIGCONT);
                let _ = signal_group(pid, libc::SIGKILL);
                let _ = wait_group_gone(pid, GROUP_KILL_GRACE);
            } else {
                let _ = child.kill();
            }
            let deadline = Instant::now() + GROUP_KILL_GRACE;
            while Instant::now() < deadline {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    return Err(io::Error::other(
                        "child identity unavailable; leader stopped, group cleanup inconclusive",
                    ));
                }
                thread::sleep(Duration::from_millis(20));
            }
            return Err(io::Error::other(
                "child identity unavailable; cleanup inconclusive, possible residual process group",
            ));
        };
        Ok(Self {
            child: Some(child),
            pid,
            start_time,
            reaped: false,
            abandoned: false,
            status: None,
            failure: None,
        })
    }

    pub fn id(&self) -> u32 {
        self.pid
    }

    pub fn stdin_mut(&mut self) -> Option<&mut ChildStdin> {
        self.child.as_mut()?.stdin.as_mut()
    }

    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.child.as_mut()?.stdin.take()
    }

    pub fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        self.child.as_mut()?.stdout.take()
    }

    /* Freeze the leader. The pid is still unreaped, so it cannot name another
     * process, and the start time check proves it is the spawned process. */
    pub fn pause_leader(&mut self) -> Result<(), String> {
        self.signal_leader(libc::SIGSTOP)
    }

    pub fn resume_leader(&mut self) -> Result<(), String> {
        self.signal_leader(libc::SIGCONT)
    }

    fn signal_leader(&mut self, signal: libc::c_int) -> Result<(), String> {
        if self.reaped || self.abandoned {
            return Err("the leader is no longer owned by this guard".to_owned());
        }
        match process_start_time(self.pid) {
            Some(value) if value == self.start_time => {}
            _ => return Err("the leader identity is not the spawned process".to_owned()),
        }
        if unsafe { libc::kill(self.pid as libc::pid_t, signal) } != 0 {
            return Err(format!(
                "signal the leader with {signal}: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    /* Test-only. The integration test kills the helper at a staged point to
     * prove the write-ahead record. The helper itself never sends SIGKILL. */
    pub fn signal_leader_for_test(&mut self, signal: libc::c_int) -> Result<(), String> {
        self.signal_leader(signal)
    }

    /* Wait until the leader is stopped by a signal, or has already exited. The
     * kernel applies SIGSTOP asynchronously, so poll for the state. */
    pub fn wait_leader_frozen(&self, timeout: Duration) -> Result<char, String> {
        let deadline = Instant::now() + timeout;
        loop {
            if process_start_time(self.pid) != Some(self.start_time) {
                return Err("leader identity cannot be verified".to_owned());
            }
            match process_state(self.pid) {
                Some(state @ ('T' | 't' | 'Z' | 'X' | 'x')) => return Ok(state),
                Some(_) => {}
                None => return Err("the leader identity disappeared".to_owned()),
            }
            if Instant::now() >= deadline {
                return Err(format!("the leader was not frozen within {timeout:?}"));
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    /* Wait for the leader to exit without reaping it. A leader that exited
     * leaves a zombie until `stop_group` has cleaned the rest of its group.
     *
     * A live group member that survives the leader is an orphan, and that is a
     * failure. The guard still cleans the orphan and reaps the leader before it
     * reports the failure, so the error never leaves a process behind. */
    pub fn wait_exit(&mut self, timeout: Duration) -> Result<ExitStatus, String> {
        if self.reaped || self.abandoned {
            if let Some(failure) = &self.failure {
                return Err(failure.clone());
            }
            return self
                .status
                .ok_or_else(|| "the process group was reaped without a status".to_owned());
        }
        let deadline = Instant::now() + timeout;
        loop {
            if self.leader_exited()? {
                break;
            }
            if Instant::now() >= deadline {
                let message = match self.stop_group(GROUP_GRACE) {
                    Ok(outcome) => format!(
                        "the process did not exit within {timeout:?}; group cleanup forced={} residual={}",
                        outcome.forced, outcome.residual
                    ),
                    Err(error) => format!(
                        "the process did not exit within {timeout:?}; group cleanup failed: {error}"
                    ),
                };
                self.failure = Some(message.clone());
                return Err(message);
            }
            thread::sleep(Duration::from_millis(50));
        }
        let outcome = self.stop_group(GROUP_GRACE)?;
        let failure = if outcome.orphaned {
            Some(format!(
                "the leader exited ({:?}) but a live group member survived it; the guard cleaned it up (forced={} residual={})",
                outcome.status, outcome.forced, outcome.residual
            ))
        } else if outcome.residual {
            Some(format!(
                "the leader exited ({:?}) but the group was not fully cleaned (forced={})",
                outcome.status, outcome.forced
            ))
        } else {
            None
        };
        if let Some(message) = failure {
            self.failure = Some(message.clone());
            return Err(message);
        }
        outcome
            .status
            .ok_or_else(|| "the process group ended without a reaped status".to_owned())
    }

    pub fn stop(&mut self, grace: Duration) -> Result<GroupStop, String> {
        if let Some(failure) = &self.failure {
            return Err(failure.clone());
        }
        let outcome = self.stop_group(grace)?;
        if outcome.orphaned || outcome.residual {
            let message = format!(
                "group cleanup failed: orphaned={} residual={}",
                outcome.orphaned, outcome.residual
            );
            self.failure = Some(message.clone());
            return Err(message);
        }
        Ok(outcome)
    }

    fn leader_exited(&self) -> Result<bool, String> {
        match process_state(self.pid) {
            Some('Z') | Some('X') | Some('x') => Ok(true),
            Some(_) => Ok(false),
            None => Err(
                "the child process identity disappeared before it was reaped; identity is uncertain"
                    .to_owned(),
            ),
        }
    }

    fn stop_group(&mut self, grace: Duration) -> Result<GroupStop, String> {
        if self.reaped {
            return Ok(GroupStop {
                status: self.status,
                forced: false,
                residual: false,
                orphaned: false,
            });
        }
        if self.abandoned {
            return Ok(GroupStop {
                status: None,
                forced: true,
                residual: true,
                orphaned: false,
            });
        }
        match process_start_time(self.pid) {
            Some(value) if value == self.start_time => {}
            Some(_) => {
                return Err(
                    "the process id now names another process; no signal was sent".to_owned(),
                );
            }
            None => {
                return Err(
                    "the process identity is gone before the group was cleaned; no signal was sent"
                        .to_owned(),
                );
            }
        }
        if process_group(self.pid) != Some(self.pid) {
            return Err(
                "the child no longer owns its process group; no signal was sent".to_owned(),
            );
        }

        let leader_exited = self.leader_exited()?;
        let others = group_members_excluding_leader(self.pid)?;
        let mut forced = false;
        let mut residual = false;
        /* Decided before any signal: the leader is already gone and a live
         * member is still running. */
        let orphaned = leader_exited && others;
        if !leader_exited || others {
            /* A frozen leader or member would hold SIGTERM pending forever. */
            signal_group(self.pid, libc::SIGCONT)?;
            signal_group(self.pid, libc::SIGTERM)?;
            let gone = wait_group_gone(self.pid, grace)?;
            if !gone {
                /* TEST-ONLY fallback. See the file comment: this test starts no
                 * tunnel, so a forced group kill skips no route cleanup. */
                signal_group(self.pid, libc::SIGKILL)?;
                let killed = wait_group_gone(self.pid, GROUP_KILL_GRACE)?;
                forced = true;
                residual = !killed;
            }
        }
        /* Never block on the leader. A process that SIGKILL cannot end, such as
         * one in uninterruptible sleep, would hang `Child::wait` forever. Poll
         * with a deadline and give up with a residual instead. */
        let status = self.reap_leader(GROUP_KILL_GRACE);
        match status {
            Some(_) => self.reaped = true,
            None => {
                residual = true;
                self.abandoned = true;
            }
        }
        self.status = status;
        if orphaned {
            self.failure = Some("the leader exited but a live group member survived it".to_owned());
        }
        Ok(GroupStop {
            status,
            forced,
            residual,
            orphaned,
        })
    }

    fn reap_leader(&mut self, budget: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + budget;
        loop {
            match self.child.as_mut()?.try_wait() {
                Ok(Some(status)) => return Some(status),
                Ok(None) => {}
                Err(_) => return None,
            }
            if Instant::now() >= deadline {
                return None;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for ProcessGroup {
    fn drop(&mut self) {
        if self.reaped || self.abandoned {
            return;
        }
        // Retry cleanup even when an earlier wait recorded a sticky failure.
        match self.stop_group(GROUP_GRACE) {
            Ok(outcome) => {
                if outcome.orphaned {
                    eprintln!(
                        "hotspotshade helper test cleanup: process group {} had a live member after its leader exited",
                        self.pid
                    );
                }
                if outcome.forced {
                    eprintln!(
                        "hotspotshade helper test cleanup: forced the test-only SIGKILL fallback for process group {}",
                        self.pid
                    );
                }
                if outcome.residual {
                    eprintln!(
                        "hotspotshade helper test cleanup: process group {} may not be fully gone",
                        self.pid
                    );
                }
            }
            Err(error) => {
                eprintln!(
                    "hotspotshade helper test cleanup: left process group {} alone: {error}",
                    self.pid
                );
            }
        }
    }
}

pub fn group_exists(pgid: u32) -> Result<bool, String> {
    group_members_excluding_leader(pgid).map(|others| others || process_state(pgid).is_some())
}

fn group_members_excluding_leader(pgid: u32) -> Result<bool, String> {
    let entries =
        fs::read_dir("/proc").map_err(|error| format!("read the process table: {error}"))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("read process entry: {error}"))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        if pid == pgid {
            continue;
        }
        let stat = match fs::read_to_string(entry.path().join("stat")) {
            Ok(value) => value,
            Err(error) if disappeared(&error) => continue,
            Err(error) => return Err(format!("read process {pid} stat: {error}")),
        };
        let fields = stat
            .rsplit_once(')')
            .ok_or_else(|| format!("invalid process {pid} stat"))?
            .1
            .split_whitespace()
            .collect::<Vec<_>>();
        let group = fields
            .get(2)
            .ok_or_else(|| format!("invalid process {pid} group"))?
            .parse::<u32>()
            .map_err(|error| format!("invalid process {pid} group: {error}"))?;
        let state = *fields
            .first()
            .ok_or_else(|| format!("invalid process {pid} state"))?;
        if group == pgid {
            /* A dead member that nobody reaped is a zombie. It cannot run or
             * be signaled, and a container init that never reaps would keep
             * it forever. Only a live member counts. */
            if matches!(state, "Z" | "X" | "x") {
                continue;
            }
            return Ok(true);
        }
    }
    Ok(false)
}

fn wait_group_gone(pgid: u32, timeout: Duration) -> Result<bool, String> {
    let deadline = Instant::now() + timeout;
    loop {
        let leader_exited = match process_state(pgid) {
            Some('Z') | Some('X') | Some('x') => true,
            Some(_) => false,
            None => return Err("leader state unavailable during cleanup".to_owned()),
        };
        let others = group_members_excluding_leader(pgid)?;
        if leader_exited && !others {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn signal_group(pgid: u32, signal: libc::c_int) -> Result<(), String> {
    let result = unsafe { libc::kill(-(pgid as libc::pid_t), signal) };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    Err(format!(
        "signal the verified process group {pgid} with {signal}: {error}"
    ))
}

/* Run an arbitrary test child in its own process group. The caller still owns
 * the child. Used for the engine build so a timed-out build cannot leave its
 * compiler workers behind. */
pub fn spawn_in_group(command: &mut Command) -> io::Result<ProcessGroup> {
    command.process_group(0);
    ProcessGroup::new(command.spawn()?)
}
