/* Hermetic lifecycle test for the real helper binary.
 *
 * This test creates the fixed packaged paths, so it must run only in a
 * disposable Linux container as root. It is skipped unless
 * HS_HELPER_INTEGRATION=1, the effective user is root, and a container marker
 * is present.
 *
 * Use the offline container wrapper in linux/README.md.
 *
 * The test starts a fake engine at the fixed engine path. The fake engine
 * writes a port and then either waits for SIGTERM or exits in a chosen way.
 * No host route, TUN device, polkit prompt, or real engine is involved.
 *
 * Both fixed-path test executables take one cross-process lock. The sandbox
 * creates the fixed directories exclusively, records the device, inode, and
 * owner of each, and removes only a matching tree after it proves that no
 * engine is alive. A process-group guard stops the whole group before it
 * reaps the leader.
 */

#![cfg(target_os = "linux")]

#[path = "support/mod.rs"]
mod support;

use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::net::Shutdown;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use support::{ProcessGroup, Sandbox};

const ENGINE: &str = support::ENGINE;
const HOME_DIR: &str = support::HOME_DIR;
const STATE: &str = support::STATE;
const ENGINE_RAN: &str = "/var/lib/hotspotshade/engine-ran";
const SECRET: &str = "abababababababababababababababababababababababababababababababab";

fn read_ready(stdout: std::process::ChildStdout) -> String {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
        let _ = sender.send(result);
    });
    receiver
        .recv_timeout(Duration::from_secs(5))
        .expect("ready line timed out")
        .expect("read ready line")
}

fn write_engine(script: &str) {
    fs::write(ENGINE, script).expect("write the fake engine");
    fs::set_permissions(ENGINE, fs::Permissions::from_mode(0o755))
        .expect("make the engine executable");
    let metadata = fs::symlink_metadata(ENGINE).expect("read the fake engine");
    assert_eq!(metadata.uid(), 0, "the fake engine must be owned by root");
    assert_eq!(
        metadata.mode() & 0o022,
        0,
        "the fake engine must not be writable by another user"
    );
}

const WAITING_ENGINE: &str = "#!/bin/sh\n\
printf 'started\\n' > /var/lib/hotspotshade/engine-ran\n\
port=\n\
while [ $# -gt 0 ]; do\n\
  if [ \"$1\" = \"--port-file\" ]; then port=$2; shift 2; else shift; fi\n\
done\n\
printf '24567\\n' > \"$port\"\n\
trap 'exit 0' TERM INT\n\
while :; do sleep 1; done\n";

const FAILING_ENGINE: &str = "#!/bin/sh\n\
port=\n\
while [ $# -gt 0 ]; do\n\
  if [ \"$1\" = \"--port-file\" ]; then port=$2; shift 2; else shift; fi\n\
done\n\
printf '24568\\n' > \"$port\"\n\
exit 9\n";

const SIGNALED_ENGINE: &str = "#!/bin/sh\n\
port=\n\
while [ $# -gt 0 ]; do\n\
  if [ \"$1\" = \"--port-file\" ]; then port=$2; shift 2; else shift; fi\n\
done\n\
printf '24569\\n' > \"$port\"\n\
kill -TERM $$\n";

fn spawn_helper(stdin: Stdio) -> (ProcessGroup, mpsc::Receiver<String>) {
    spawn_helper_with_env(stdin, &[])
}

fn spawn_helper_with_env(
    stdin: Stdio,
    envs: &[(&str, &str)],
) -> (ProcessGroup, mpsc::Receiver<String>) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hotspotshade-helper"));
    command
        .env("PKEXEC_UID", "1000")
        .stdin(stdin)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0);
    for (key, value) in envs {
        command.env(key, value);
    }
    let mut child = command.spawn().expect("start the helper");
    let stdout = child.stdout.take().expect("the helper stdout");
    let group = ProcessGroup::new(child).expect("record the helper process identity");
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    (group, receiver)
}

fn start_helper() -> (ProcessGroup, mpsc::Receiver<String>) {
    spawn_helper(Stdio::piped())
}

/* A real child stdio socketpair, as the Electron client creates it. The parent
 * keeps the write half so a test can half-close it with shutdown(Write) exactly
 * as Node `end()` does, without closing the descriptor. */
fn start_helper_with_socketpair() -> (ProcessGroup, mpsc::Receiver<String>, UnixStream) {
    let (child_end, parent_end) = UnixStream::pair().expect("create the helper socket pair");
    let stdin = Stdio::from(OwnedFd::from(child_end));
    let (child, lines) = spawn_helper(stdin);
    (child, lines, parent_end)
}

fn send_request(group: &mut ProcessGroup) {
    let stdin = group.stdin_mut().expect("the helper stdin");
    write!(stdin, "HS1\n{SECRET}\n").expect("write the helper request");
    stdin.flush().expect("flush the helper request");
}

fn send_socket_request(writer: &mut UnixStream) {
    write!(writer, "HS1\n{SECRET}\n").expect("write the helper request");
    writer.flush().expect("flush the helper request");
}

fn wait_for_line(receiver: &mpsc::Receiver<String>, prefix: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(left) {
            Ok(line) if line.starts_with(prefix) => return line,
            Ok(_) => {}
            Err(error) => panic!("no {prefix} line: {error}"),
        }
    }
}

fn wait_exit(group: &mut ProcessGroup, timeout: Duration) -> ExitStatus {
    group
        .wait_exit(timeout)
        .unwrap_or_else(|error| panic!("the helper did not exit cleanly: {error}"))
}

fn close_stdin(group: &mut ProcessGroup) {
    drop(group.take_stdin());
}

fn write_live_state() {
    let pid = std::process::id();
    let start_time = support::process_start_time(pid).expect("read this process start time");
    let text = support::engine_state_text(pid, start_time);
    fs::write(STATE, text).expect("write the state");
    fs::set_permissions(STATE, fs::Permissions::from_mode(0o600)).expect("make the state private");
}

fn read_state_text() -> String {
    fs::read_to_string(STATE).expect("read the engine state")
}

fn assert_state_phase(phase: &str) {
    let text = read_state_text();
    let last = text.lines().last().expect("the state has a process line");
    assert!(
        last.starts_with(phase),
        "the state phase must be {phase}: {last}"
    );
}

fn wait_until(mut condition: impl FnMut() -> bool, timeout: Duration, what: &str) {
    let deadline = Instant::now() + timeout;
    loop {
        if condition() {
            return;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for_engine_process_gone() {
    wait_until(
        || !support::engine_process_alive().expect("read the process table"),
        Duration::from_secs(10),
        "the engine process to exit",
    );
}

fn create_sandbox() -> Sandbox {
    Sandbox::create().expect("create the fixed test roots exclusively")
}

fn finish(sandbox: &mut Sandbox) {
    sandbox.cleanup().expect("remove the fixed test roots");
}

#[test]
fn the_real_helper_lifecycle_is_fail_closed() {
    if !support::enabled() {
        eprintln!(
            "skipping the real helper lifecycle test; it needs HS_HELPER_INTEGRATION=1, root, and a disposable container"
        );
        return;
    }
    let _reservation = support::reserve();
    let mut sandbox = create_sandbox();
    write_engine(WAITING_ENGINE);

    /* One normal start and stop proves the helper starts the engine, reports
     * the port, and exits cleanly when its request pipe closes. */
    let (mut first, first_lines) = start_helper();
    send_request(&mut first);
    wait_for_line(&first_lines, "HS_READY", Duration::from_secs(5));
    wait_for_line(&first_lines, "HS_PORT", Duration::from_secs(5));

    /* A second helper must refuse while the first one holds the lock. */
    let (mut second, _second_lines) = start_helper();
    send_request(&mut second);
    let second_status = wait_exit(&mut second, Duration::from_secs(5));
    assert_eq!(
        second_status.code(),
        Some(6),
        "a second helper must refuse the lock"
    );

    close_stdin(&mut first);
    let first_status = wait_exit(&mut first, Duration::from_secs(20));
    assert_eq!(
        first_status.code(),
        Some(0),
        "the first helper stops cleanly"
    );
    assert!(!Path::new(STATE).exists(), "the state is removed");

    /* A stale state record for a live process must block a later helper even
     * when the lock is free. */
    write_live_state();
    let (mut third, _third_lines) = start_helper();
    send_request(&mut third);
    let third_status = wait_exit(&mut third, Duration::from_secs(5));
    assert_eq!(
        third_status.code(),
        Some(6),
        "a live previous engine must block the start"
    );
    fs::remove_file(STATE).expect("remove the test state");

    /* An engine that exits with a signal is not a clean stop. */
    write_engine(SIGNALED_ENGINE);
    let (mut signaled, _signaled_lines) = start_helper();
    send_request(&mut signaled);
    let signaled_status = wait_exit(&mut signaled, Duration::from_secs(5));
    assert_eq!(
        signaled_status.code(),
        Some(4),
        "a signaled engine is reported"
    );

    /* An engine that exits non-zero is not a clean stop. */
    write_engine(FAILING_ENGINE);
    let (mut failed, _failed_lines) = start_helper();
    send_request(&mut failed);
    let failed_status = wait_exit(&mut failed, Duration::from_secs(5));
    assert_eq!(failed_status.code(), Some(5), "a failed engine is reported");

    finish(&mut sandbox);
}

/* The Electron client hands the helper a child stdio socketpair, not a pipe.
 * On that channel `end()` is a write half-close: the parent descriptor stays
 * open, so the helper sees EOF without POLLHUP. These tests use the real
 * socketpair behavior and a fake engine. */

#[test]
fn a_socketpair_closed_before_hs_ready_starts_no_engine() {
    if !support::enabled() {
        eprintln!(
            "skipping the socketpair abandonment test; it needs HS_HELPER_INTEGRATION=1, root, and a disposable container"
        );
        return;
    }
    let _reservation = support::reserve();
    let mut sandbox = create_sandbox();
    write_engine(WAITING_ENGINE);
    let _ = fs::remove_file(ENGINE_RAN);

    /* Queue the request and the half-close before the helper can read. The
     * read still returns the two lines, then the guard sees EOF. */
    let (child_end, mut writer) = UnixStream::pair().expect("create the helper socket pair");
    send_socket_request(&mut writer);
    writer
        .shutdown(Shutdown::Write)
        .expect("half-close the helper request");
    let (mut child, _lines) = spawn_helper(Stdio::from(OwnedFd::from(child_end)));

    let status = wait_exit(&mut child, Duration::from_secs(10));
    assert_eq!(
        status.code(),
        Some(7),
        "a late helper reports that it was abandoned"
    );
    assert!(
        !Path::new(ENGINE_RAN).exists(),
        "no engine may start after the app gave up"
    );
    assert!(
        !Path::new(STATE).exists(),
        "no engine state may be recorded"
    );
    drop(writer);
    finish(&mut sandbox);
}

#[test]
fn a_socketpair_half_closed_after_hs_ready_leaves_no_engine() {
    if !support::enabled() {
        eprintln!(
            "skipping the socketpair abandonment test; it needs HS_HELPER_INTEGRATION=1, root, and a disposable container"
        );
        return;
    }
    let _reservation = support::reserve();
    let mut sandbox = create_sandbox();
    write_engine(WAITING_ENGINE);
    let _ = fs::remove_file(ENGINE_RAN);

    let (mut child, lines, mut writer) = start_helper_with_socketpair();
    send_socket_request(&mut writer);
    wait_for_line(&lines, "HS_READY", Duration::from_secs(5));
    /* The helper may see the half-close before or after it launches the engine.
     * Both outcomes are safe: either no engine starts, or a started engine is
     * stopped and reaped before the helper exits. */
    writer
        .shutdown(Shutdown::Write)
        .expect("half-close the helper request");
    let status = wait_exit(&mut child, Duration::from_secs(25));
    assert!(
        matches!(status.code(), Some(0) | Some(4) | Some(7)),
        "an abandoned helper reports a stop or an abandonment, not a hang: {status:?}"
    );
    assert!(
        !Path::new(STATE).exists(),
        "an engine started after a late half-close must not be left behind"
    );
    drop(writer);
    finish(&mut sandbox);
}

#[test]
fn a_socketpair_half_closed_while_the_engine_runs_stops_it() {
    if !support::enabled() {
        eprintln!(
            "skipping the socketpair stop test; it needs HS_HELPER_INTEGRATION=1, root, and a disposable container"
        );
        return;
    }
    let _reservation = support::reserve();
    let mut sandbox = create_sandbox();
    write_engine(WAITING_ENGINE);
    let _ = fs::remove_file(ENGINE_RAN);

    let (mut child, lines, mut writer) = start_helper_with_socketpair();
    send_socket_request(&mut writer);
    wait_for_line(&lines, "HS_PORT", Duration::from_secs(10));
    assert!(Path::new(ENGINE_RAN).exists(), "the fake engine started");

    /* This is the app stop path on a socketpair. It proves the request reader
     * treats a write half-close as EOF and stops the running engine, rather
     * than waiting for a POLLHUP that a half-close never sends. */
    writer
        .shutdown(Shutdown::Write)
        .expect("half-close the helper request");
    let status = wait_exit(&mut child, Duration::from_secs(25));
    assert_eq!(
        status.code(),
        Some(0),
        "the half-close stops the running fake engine cleanly"
    );
    assert!(
        !Path::new(STATE).exists(),
        "the stopped engine state is removed"
    );
    drop(writer);
    finish(&mut sandbox);
}

#[test]
fn the_helper_runs_the_checked_canonical_engine() {
    if !support::enabled() {
        eprintln!(
            "skipping the canonical engine test; it needs HS_HELPER_INTEGRATION=1, root, and a disposable container"
        );
        return;
    }
    let _reservation = support::reserve();
    let mut sandbox = create_sandbox();
    write_engine(WAITING_ENGINE);
    let real = format!("{}/hotspotshade-engine", support::ENGINE_DIR);
    fs::rename(ENGINE, &real).expect("move the fake engine");
    std::os::unix::fs::symlink(&real, ENGINE).expect("link the fixed engine path");
    let _ = fs::remove_file(ENGINE_RAN);

    let (mut child, lines) = start_helper();
    send_request(&mut child);
    wait_for_line(&lines, "HS_PORT", Duration::from_secs(10));
    assert!(
        Path::new(ENGINE_RAN).exists(),
        "the canonical engine target ran"
    );
    close_stdin(&mut child);
    let status = wait_exit(&mut child, Duration::from_secs(20));
    assert_eq!(status.code(), Some(0), "the canonical engine stops cleanly");
    finish(&mut sandbox);
}

/* A pre-existing fixed root is not ours. The sandbox must refuse it and leave
 * it exactly as it found it. */
#[test]
fn a_preexisting_engine_root_is_refused_and_kept() {
    if !support::enabled() {
        eprintln!(
            "skipping the pre-existing root test; it needs HS_HELPER_INTEGRATION=1, root, and a disposable container"
        );
        return;
    }
    let _reservation = support::reserve();
    assert!(
        !Path::new(support::ENGINE_ROOT).exists(),
        "the container must start without the fixed engine root"
    );
    assert!(
        !Path::new(HOME_DIR).exists(),
        "the container must start without the fixed engine home"
    );
    fs::create_dir(support::ENGINE_ROOT).expect("create the sentinel root");
    fs::set_permissions(
        Path::new(support::ENGINE_ROOT),
        fs::Permissions::from_mode(0o755),
    )
    .expect("make the sentinel root readable");
    fs::write(Path::new(support::ENGINE_ROOT).join("sentinel"), b"keep")
        .expect("write the sentinel");
    let mut sentinel = support::OwnedDir::adopt(Path::new(support::ENGINE_ROOT), 0o755)
        .expect("own the sentinel root");

    let result = Sandbox::create();
    assert!(result.is_err(), "a pre-existing fixed root must be refused");
    assert!(
        sentinel.path().join("sentinel").exists(),
        "the pre-existing root must be kept"
    );
    assert!(
        !Path::new(HOME_DIR).exists(),
        "the refused sandbox must not create the home"
    );
    sentinel.cleanup().expect("remove the sentinel root");
}

/* If the home already exists, the sandbox must remove only the engine root it
 * just created and keep the foreign home. */
#[test]
fn a_preexisting_home_is_refused_and_the_new_engine_root_is_rolled_back() {
    if !support::enabled() {
        eprintln!(
            "skipping the pre-existing home test; it needs HS_HELPER_INTEGRATION=1, root, and a disposable container"
        );
        return;
    }
    let _reservation = support::reserve();
    assert!(
        !Path::new(support::ENGINE_ROOT).exists(),
        "the container must start without the fixed engine root"
    );
    assert!(
        !Path::new(HOME_DIR).exists(),
        "the container must start without the fixed engine home"
    );
    fs::create_dir(HOME_DIR).expect("create the sentinel home");
    fs::set_permissions(HOME_DIR, fs::Permissions::from_mode(0o700))
        .expect("make the sentinel home private");
    fs::write(Path::new(HOME_DIR).join("sentinel"), b"keep").expect("write the sentinel");
    let mut sentinel =
        support::OwnedDir::adopt(Path::new(HOME_DIR), 0o700).expect("own the sentinel home");

    let result = Sandbox::create();
    assert!(result.is_err(), "a pre-existing fixed home must be refused");
    assert!(
        !Path::new(support::ENGINE_ROOT).exists(),
        "the engine root created by the failed setup must be rolled back"
    );
    assert!(
        sentinel.path().join("sentinel").exists(),
        "the pre-existing home must be kept"
    );
    sentinel.cleanup().expect("remove the sentinel home");
}

/* A replacement made before cleanup must be refused and left intact. This
 * does not test or eliminate a swap after the final identity check. */
#[test]
fn a_swapped_directory_is_not_removed() {
    if !support::enabled() {
        eprintln!(
            "skipping the swapped directory test; it needs HS_HELPER_INTEGRATION=1, root, and a disposable container"
        );
        return;
    }
    let _reservation = support::reserve();
    let mut base = support::private_temp_dir("swap").expect("create the private test root");
    let root_path = base.path().join("root");
    let replacement_path = base.path().join("replacement");
    let moved_path = base.path().join("moved");
    let mut original =
        support::OwnedDir::create(&root_path, 0o700).expect("create the original root");
    fs::write(root_path.join("original"), b"original").expect("write the original sentinel");
    let mut replacement =
        support::OwnedDir::create(&replacement_path, 0o700).expect("create the replacement root");
    fs::write(replacement_path.join("replacement"), b"replacement")
        .expect("write the replacement sentinel");

    fs::rename(&root_path, &moved_path).expect("move the original root aside");
    fs::rename(&replacement_path, &root_path).expect("swap in the replacement root");
    let result = original.cleanup();
    assert!(result.is_err(), "a swapped root must be refused");
    assert!(
        root_path.join("replacement").exists(),
        "the replacement tree must be kept"
    );
    replacement.forget();
    base.cleanup().expect("remove the private test root");
}

/* Cleanup must never delete the fixed trees while an engine may still use
 * them. A live state record blocks it and keeps every tree. */
#[test]
fn cleanup_is_refused_while_an_engine_lives() {
    if !support::enabled() {
        eprintln!(
            "skipping the live engine cleanup test; it needs HS_HELPER_INTEGRATION=1, root, and a disposable container"
        );
        return;
    }
    let _reservation = support::reserve();
    let mut sandbox = create_sandbox();
    write_engine(WAITING_ENGINE);
    write_live_state();

    let result = sandbox.cleanup();
    assert!(result.is_err(), "cleanup must refuse while an engine lives");
    assert!(Path::new(ENGINE).exists(), "the engine tree must be kept");
    assert!(Path::new(STATE).exists(), "the state record must be kept");
    sandbox
        .verify()
        .expect("the kept trees keep their identity");

    fs::remove_file(STATE).expect("remove the test state");
    finish(&mut sandbox);
    assert!(
        !Path::new(support::ENGINE_ROOT).exists(),
        "the engine root is removed once no engine lives"
    );
    assert!(
        !Path::new(HOME_DIR).exists(),
        "the home is removed once no engine lives"
    );
}

/* A timeout in the test must stop the helper and the root engine it owns. A
 * group stop that signals only the leader would leave the engine behind. */
#[test]
fn stopping_the_helper_group_leaves_no_engine() {
    if !support::enabled() {
        eprintln!(
            "skipping the group stop test; it needs HS_HELPER_INTEGRATION=1, root, and a disposable container"
        );
        return;
    }
    let _reservation = support::reserve();
    let mut sandbox = create_sandbox();
    write_engine(WAITING_ENGINE);
    let _ = fs::remove_file(ENGINE_RAN);

    let (mut child, lines) = start_helper();
    send_request(&mut child);
    wait_for_line(&lines, "HS_PORT", Duration::from_secs(10));
    assert!(
        support::engine_alive().expect("read the process table"),
        "the engine runs before the stop"
    );

    /* The stop path a timeout takes. The request pipe stays open. */
    let outcome = child
        .stop(Duration::from_secs(30))
        .expect("stop the helper group");
    assert!(!outcome.residual, "no helper group member is left behind");
    assert!(
        !support::engine_alive().expect("read the process table"),
        "the root engine must not outlive its stopped helper group"
    );
    drop(child);
    let _ = fs::remove_file(STATE);
    finish(&mut sandbox);
}

#[test]
fn an_unsafe_or_contended_lock_is_refused() {
    if !support::enabled() {
        eprintln!(
            "skipping the lock test; it needs HS_HELPER_INTEGRATION=1, root, and a disposable container"
        );
        return;
    }
    let mut base = support::private_temp_dir("lock").expect("create the private test root");
    let uid = unsafe { libc::geteuid() };
    let lock_path = base.path().join("lock");
    let first = support::acquire_lock_at(&lock_path, uid, Duration::ZERO).expect("take the lock");
    let second = support::acquire_lock_at(&lock_path, uid, Duration::from_millis(200));
    assert_eq!(
        second.expect_err("a second holder must be refused").kind(),
        io::ErrorKind::TimedOut
    );
    drop(first);
    let third =
        support::acquire_lock_at(&lock_path, uid, Duration::ZERO).expect("take the released lock");
    drop(third);

    let unsafe_path = base.path().join("unsafe-lock");
    fs::write(&unsafe_path, b"lock").expect("write the unsafe lock");
    fs::set_permissions(&unsafe_path, fs::Permissions::from_mode(0o666))
        .expect("widen the unsafe lock");
    assert_eq!(
        support::acquire_lock_at(&unsafe_path, uid, Duration::ZERO)
            .expect_err("a shared lock must be refused")
            .kind(),
        io::ErrorKind::PermissionDenied
    );

    let target = base.path().join("lock-target");
    fs::write(&target, b"target").expect("write the symlink target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
        .expect("make the symlink target private");
    let link = base.path().join("lock-link");
    std::os::unix::fs::symlink(&target, &link).expect("link the lock path");
    assert!(
        support::acquire_lock_at(&link, uid, Duration::ZERO).is_err(),
        "a symlink lock must be refused"
    );
    base.cleanup().expect("remove the private test root");
}

/* The group guard must clean the rest of the group before it reaps the leader,
 * even after a stubborn member ignores SIGTERM. */
#[test]
fn a_timed_out_group_is_cleaned_without_orphans() {
    if !support::enabled() {
        eprintln!(
            "skipping the process group timeout test; it needs HS_HELPER_INTEGRATION=1, root, and a disposable container"
        );
        return;
    }
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg("trap '' TERM; echo ready; while :; do sleep 1; done")
        .stdout(Stdio::piped());
    let mut group = support::spawn_in_group(&mut command).expect("start the stubborn test group");
    let pgid = group.id();
    /* Wait until the shell ignores SIGTERM, or the signal could kill it first
     * and the test would not exercise the forced fallback. */
    let stdout = group.take_stdout().expect("the stubborn group stdout");
    let ready = read_ready(stdout);
    assert_eq!(ready.trim(), "ready", "the stubborn shell is ready");
    let outcome = group
        .stop(Duration::from_millis(250))
        .expect("stop the stubborn test group");
    assert!(
        outcome.forced,
        "the test-only SIGKILL fallback stops a group that ignores SIGTERM"
    );
    assert!(!outcome.residual, "no group member is left behind");
    assert!(
        !support::group_exists(pgid).expect("read the process table"),
        "the timed-out group is gone"
    );
}

/* An orphan is a failure, not a success. The guard must still clean the orphan
 * and reap the leader before it reports the failure. */
#[test]
fn an_orphaned_group_member_fails_the_wait_and_is_still_cleaned() {
    if !support::enabled() {
        eprintln!(
            "skipping the process group orphan test; it needs HS_HELPER_INTEGRATION=1, root, and a disposable container"
        );
        return;
    }
    let mut command = Command::new("/bin/sh");
    command.arg("-c").arg("sleep 30 & exit 0");
    let mut group = support::spawn_in_group(&mut command).expect("start the test group");
    let pgid = group.id();
    let error = group
        .wait_exit(Duration::from_secs(5))
        .expect_err("a surviving group member must fail the wait");
    assert!(
        error.contains("survived"),
        "the failure names the orphan: {error}"
    );
    assert!(
        !support::group_exists(pgid).expect("read the process table"),
        "the orphan is gone and the leader is reaped"
    );
    /* A later call keeps reporting the failure. */
    assert!(
        group.wait_exit(Duration::from_secs(1)).is_err(),
        "the orphan failure is sticky"
    );
    assert!(
        group.stop(Duration::ZERO).is_err(),
        "stop also retains the orphan failure"
    );
}

#[test]
fn stop_reports_an_orphan_and_keeps_the_failure() {
    if !support::enabled() {
        return;
    }
    let mut command = Command::new("/bin/sh");
    command.arg("-c").arg("sleep 30 & exit 0");
    let mut group = support::spawn_in_group(&mut command).expect("start group");
    let pgid = group.id();
    group
        .wait_leader_frozen(Duration::from_secs(5))
        .expect("leader exits");
    assert!(group.stop(Duration::from_secs(2)).is_err());
    assert!(group.stop(Duration::ZERO).is_err());
    assert!(!support::group_exists(pgid).expect("inspect group"));
}

#[test]
fn wait_timeout_remains_a_failure_after_cleanup() {
    if !support::enabled() {
        return;
    }
    let mut command = Command::new("/bin/sh");
    command.arg("-c").arg("exec sleep 30");
    let mut group = support::spawn_in_group(&mut command).expect("start group");
    assert!(group.wait_exit(Duration::from_millis(100)).is_err());
    assert!(group.wait_exit(Duration::ZERO).is_err());
    assert!(group.stop(Duration::ZERO).is_err());
}

#[test]
fn a_clean_leader_exit_with_no_orphan_succeeds() {
    if !support::enabled() {
        eprintln!(
            "skipping the process group clean exit test; it needs HS_HELPER_INTEGRATION=1, root, and a disposable container"
        );
        return;
    }
    let mut command = Command::new("/bin/sh");
    command.arg("-c").arg("sleep 0.2; exit 0");
    let mut group = support::spawn_in_group(&mut command).expect("start the test group");
    let pgid = group.id();
    let status = group
        .wait_exit(Duration::from_secs(5))
        .expect("a leader with no orphan exits cleanly");
    assert!(status.success(), "the leader exits cleanly");
    assert!(
        !support::group_exists(pgid).expect("read the process table"),
        "the group is gone"
    );
}

/* A frozen leader holds SIGTERM pending. The stop path must resume it first,
 * and must do so inside its bounded grace, without the SIGKILL fallback. */
#[test]
fn a_paused_leader_is_resumed_and_stopped_by_sigterm() {
    if !support::enabled() {
        eprintln!(
            "skipping the paused leader test; it needs HS_HELPER_INTEGRATION=1, root, and a disposable container"
        );
        return;
    }
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg("echo ready; while :; do sleep 1; done")
        .stdout(Stdio::piped());
    let mut group = support::spawn_in_group(&mut command).expect("start the test group");
    let pgid = group.id();
    let stdout = group.take_stdout().expect("the test group stdout");
    let ready = read_ready(stdout);
    assert_eq!(ready.trim(), "ready", "the shell is ready");
    group.pause_leader().expect("freeze the leader");
    let state = group
        .wait_leader_frozen(Duration::from_secs(5))
        .expect("the leader is frozen");
    assert!(
        state == 'T' || state == 't',
        "the leader is stopped, not running: {state}"
    );
    let outcome = group
        .stop(Duration::from_secs(10))
        .expect("stop the frozen group");
    assert!(!outcome.forced, "SIGTERM after SIGCONT is enough");
    assert!(!outcome.residual, "nothing is left behind");
    assert!(
        !support::group_exists(pgid).expect("read the process table"),
        "the frozen group is gone"
    );
}

/* The state record must be usable across boots and PID namespaces. A record
 * that only carried a pid and a start time could match an unrelated process
 * after a reboot. */
#[test]
fn a_state_record_names_the_boot_and_pid_namespace() {
    if !support::enabled() {
        eprintln!(
            "skipping the state identity test; it needs HS_HELPER_INTEGRATION=1, root, and a disposable container"
        );
        return;
    }
    let _reservation = support::reserve();
    let mut sandbox = create_sandbox();
    write_engine(WAITING_ENGINE);

    let (mut child, lines) = start_helper();
    send_request(&mut child);
    wait_for_line(&lines, "HS_PORT", Duration::from_secs(10));
    let text = read_state_text();
    let boot = support::boot_id().expect("read the kernel boot id");
    let (dev, ino) = support::pid_namespace().expect("read this PID namespace");
    assert!(
        text.contains(&format!("BOOT {boot}\n")),
        "the state names this boot: {text}"
    );
    assert!(
        text.contains(&format!("NS {dev} {ino}\n")),
        "the state names this PID namespace: {text}"
    );
    assert_state_phase("ENGINE");

    close_stdin(&mut child);
    let status = wait_exit(&mut child, Duration::from_secs(20));
    assert_eq!(status.code(), Some(0), "the engine stops cleanly");
    assert!(!Path::new(STATE).exists(), "the state is removed");
    finish(&mut sandbox);
}

/* A helper killed after the spawn but before the ENGINE record leaves the
 * write-ahead PENDING record. The engine gets SIGTERM from the parent-death
 * signal, but no later helper may start over the unknown engine identity. */
#[test]
fn a_killed_helper_leaves_a_pending_record_that_blocks_a_second_start() {
    if !support::enabled() {
        eprintln!(
            "skipping the killed-helper pending test; it needs HS_HELPER_INTEGRATION=1, root, and a disposable container"
        );
        return;
    }
    let _reservation = support::reserve();
    let mut sandbox = create_sandbox();
    write_engine(WAITING_ENGINE);
    let _ = fs::remove_file(ENGINE_RAN);

    let (mut child, lines) = spawn_helper_with_env(
        Stdio::piped(),
        &[("HS_HELPER_TEST_DELAY_AFTER_SPAWN_MS", "5000")],
    );
    send_request(&mut child);
    wait_for_line(&lines, "HS_READY", Duration::from_secs(5));
    wait_until(
        || Path::new(ENGINE_RAN).exists(),
        Duration::from_secs(5),
        "the fake engine to start",
    );
    assert_state_phase("PENDING");
    assert!(
        support::engine_process_alive().expect("read the process table"),
        "the fake engine runs while the helper is paused"
    );

    child
        .signal_leader_for_test(libc::SIGKILL)
        .expect("kill the helper after the spawn");
    wait_for_engine_process_gone();
    let status = wait_exit(&mut child, Duration::from_secs(10));
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "the test killed the helper"
    );
    assert!(Path::new(STATE).exists(), "the pending record is kept");
    assert_state_phase("PENDING");

    let (mut second, _second_lines) = start_helper();
    send_request(&mut second);
    let second_status = wait_exit(&mut second, Duration::from_secs(10));
    assert_eq!(
        second_status.code(),
        Some(8),
        "an abandoned pending start is uncertain, not a new start"
    );
    assert!(Path::new(STATE).exists(), "the pending record is preserved");

    fs::remove_file(STATE).expect("remove the test pending record");
    finish(&mut sandbox);
}

/* Once the ENGINE record exists and the recorded engine is gone, a later
 * helper may remove the stale record and start normally. */
#[test]
fn a_killed_helper_after_the_engine_record_is_recovered_when_the_engine_is_gone() {
    if !support::enabled() {
        eprintln!(
            "skipping the killed-helper recovery test; it needs HS_HELPER_INTEGRATION=1, root, and a disposable container"
        );
        return;
    }
    let _reservation = support::reserve();
    let mut sandbox = create_sandbox();
    write_engine(WAITING_ENGINE);
    let _ = fs::remove_file(ENGINE_RAN);

    let (mut first, first_lines) = start_helper();
    send_request(&mut first);
    wait_for_line(&first_lines, "HS_PORT", Duration::from_secs(10));
    assert_state_phase("ENGINE");
    first
        .signal_leader_for_test(libc::SIGKILL)
        .expect("kill the helper after the engine record");
    wait_for_engine_process_gone();
    let first_status = wait_exit(&mut first, Duration::from_secs(10));
    assert_eq!(first_status.signal(), Some(libc::SIGKILL));
    assert!(Path::new(STATE).exists(), "the engine record survives");

    let (mut second, second_lines) = start_helper();
    send_request(&mut second);
    wait_for_line(&second_lines, "HS_PORT", Duration::from_secs(10));
    assert_state_phase("ENGINE");
    close_stdin(&mut second);
    let second_status = wait_exit(&mut second, Duration::from_secs(20));
    assert_eq!(
        second_status.code(),
        Some(0),
        "the recovered helper stops cleanly"
    );
    assert!(!Path::new(STATE).exists(), "the state is removed");
    finish(&mut sandbox);
}

/* A failed pre-spawn write-ahead record must stop the launch before any
 * engine exists. A directory at the helper's private temporary state path is a
 * deterministic write failure that no cleanup path may silently replace. */
#[test]
fn a_state_write_failure_before_the_spawn_starts_no_engine() {
    if !support::enabled() {
        eprintln!(
            "skipping the pre-spawn state failure test; it needs HS_HELPER_INTEGRATION=1, root, and a disposable container"
        );
        return;
    }
    let _reservation = support::reserve();
    let mut sandbox = create_sandbox();
    write_engine(WAITING_ENGINE);
    let _ = fs::remove_file(ENGINE_RAN);

    let (mut child, _lines) = start_helper();
    let temporary = Path::new(STATE).with_extension(format!("tmp-{}", child.id()));
    fs::create_dir(&temporary).expect("put a directory at the pending temporary path");
    send_request(&mut child);
    let status = wait_exit(&mut child, Duration::from_secs(10));
    assert_eq!(
        status.code(),
        Some(1),
        "a failed start record is a local setup failure"
    );
    assert!(
        !Path::new(ENGINE_RAN).exists(),
        "no engine may start without a pending record"
    );
    let metadata = fs::symlink_metadata(&temporary).expect("the temporary path is kept");
    assert!(metadata.is_dir(), "the temporary path is not replaced");

    fs::remove_dir(&temporary).expect("remove the test directory at the temporary path");
    finish(&mut sandbox);
}

/* Cleanup failure has its own code. An engine that exits 0 must not hide a
 * state file that the helper could not remove. The documented container drops
 * CAP_DAC_OVERRIDE, so a read-only home makes the unlink fail as root. */
#[test]
fn an_unremovable_state_reports_cleanup_failure() {
    if !support::enabled() {
        eprintln!(
            "skipping the cleanup failure test; it needs HS_HELPER_INTEGRATION=1, root, and a disposable container"
        );
        return;
    }
    let _reservation = support::reserve();
    let mut sandbox = create_sandbox();
    write_engine(WAITING_ENGINE);

    let (mut child, lines) = start_helper();
    send_request(&mut child);
    wait_for_line(&lines, "HS_PORT", Duration::from_secs(10));
    assert_state_phase("ENGINE");
    fs::set_permissions(HOME_DIR, fs::Permissions::from_mode(0o500))
        .expect("make the state home read-only");

    close_stdin(&mut child);
    let status = wait_exit(&mut child, Duration::from_secs(30));
    fs::set_permissions(HOME_DIR, fs::Permissions::from_mode(0o700))
        .expect("restore the state home");
    assert_eq!(
        status.code(),
        Some(9),
        "a cleanup failure is not an engine error and not a clean stop"
    );
    assert!(Path::new(STATE).exists(), "the unremovable state is kept");

    finish(&mut sandbox);
}

/* A pending record left by a killed helper has no engine identity. Even when
 * no engine process remains, the next helper must not guess. */
#[test]
fn a_pending_record_from_a_dead_helper_is_uncertain_and_kept() {
    if !support::enabled() {
        eprintln!(
            "skipping the dead pending record test; it needs HS_HELPER_INTEGRATION=1, root, and a disposable container"
        );
        return;
    }
    let _reservation = support::reserve();
    let mut sandbox = create_sandbox();
    write_engine(WAITING_ENGINE);
    let _ = fs::remove_file(ENGINE_RAN);
    let text = support::pending_state_text(u32::MAX, 1);
    fs::write(STATE, text).expect("write the pending state");
    fs::set_permissions(STATE, fs::Permissions::from_mode(0o600)).expect("make the state private");

    let (mut child, _lines) = start_helper();
    send_request(&mut child);
    let status = wait_exit(&mut child, Duration::from_secs(10));
    assert_eq!(status.code(), Some(8), "the pending record is uncertain");
    assert!(Path::new(STATE).exists(), "the pending record is kept");
    assert!(!Path::new(ENGINE_RAN).exists(), "no engine was started");

    fs::remove_file(STATE).expect("remove the test pending record");
    finish(&mut sandbox);
}
