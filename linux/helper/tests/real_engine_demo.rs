/* Hermetic real-engine lifecycle test for the real pkexec helper.
 *
 * What this proves, inside one disposable Linux container:
 *   - the current Rust engine builds from source into a private checked
 *     directory under the sandbox, or a staged prebuilt engine is accepted;
 *   - the engine is staged at the fixed packaged path, owned by root, mode
 *     0755, and not group or other writable;
 *   - the real helper accepts a real descriptor request with PKEXEC_UID set,
 *     starts the real engine, and reports HS_READY and HS_PORT;
 *   - the engine never carries the per-launch secret on its command line;
 *   - the authenticated loopback GUI answers GET /api/status from the real
 *     backend, and a wrong or missing bearer secret gets 401;
 *   - the GUI listener is on 127.0.0.1 only;
 *   - the helper removes its private port directory and the engine state
 *     record, and the engine exits when the parent request channel closes;
 *   - a second start after the clean stop proves the lock and the fixed paths
 *     are reusable.
 *
 * What this does not prove:
 *   - the packaged .deb layout, polkit, DBus, or the Electron app;
 *   - a live root host, a hotspot, a carrier, or a tunnel;
 *   - route or TUN cleanup, because this test starts no tunnel.
 *
 * The test starts no tunnel, opens no TUN device, and changes no route. Its
 * request uses loopback; the wrapper disables container networking. It needs
 * no polkit daemon. It is skipped unless HS_HELPER_INTEGRATION=1, the effective user is
 * root, and a container marker is present.
 *
 * Run it only in a disposable container using the offline wrapper in
 * linux/README.md.
 */

#![cfg(target_os = "linux")]

#[path = "support/mod.rs"]
mod support;

use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use support::{ProcessGroup, Sandbox};

const ENGINE_ROOT: &str = support::ENGINE_ROOT;
const ENGINE_DIR: &str = support::ENGINE_DIR;
const ENGINE: &str = support::ENGINE;
const HOME_DIR: &str = support::HOME_DIR;
const STATE: &str = support::STATE;

/* Fixed public test vectors. The engine accepts 64 lowercase hex characters.
 * These are not secrets and must never be replaced with a real token. */
const SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const WRONG_SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdee";

/* Included at compile time from the same source used to build the helper. */
fn helper_eof_grace() -> Duration {
    let source = include_str!("../src/main.rs");
    let value = source
        .lines()
        .find_map(|line| {
            line.strip_prefix("const EOF_GRACE: Duration = Duration::from_secs(")
                .and_then(|line| line.strip_suffix(");"))
        })
        .expect("inconclusive: cannot inspect helper EOF grace in build source");
    Duration::from_secs(
        value
            .parse()
            .expect("inconclusive: invalid helper EOF grace"),
    )
}
const LIVENESS_RELEASE_BUDGET: Duration = Duration::from_secs(5);
const ENGINE_LIVENESS_EXIT_BUDGET: Duration = Duration::from_secs(30);

const HTTP_SOCKET_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP_RESPONSE_BUDGET: Duration = Duration::from_secs(10);

fn assert_public_vector() {
    for value in [SECRET, WRONG_SECRET] {
        assert_eq!(value.len(), 64, "a test secret must be 64 characters");
        assert!(
            value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "a test secret must be lowercase hex"
        );
    }
    assert_ne!(SECRET, WRONG_SECRET, "the wrong secret must differ");
}

/* Return the real engine binary. HS_REAL_ENGINE names a staged build. Without
 * it, build the current engine from source in the sandbox home. The build
 * directory is created exclusively, is private, and is removed with the
 * sandbox. Never use a predictable shared /tmp path. */
fn engine_source(home: &Path) -> PathBuf {
    if let Some(value) = env::var_os("HS_REAL_ENGINE") {
        let path = PathBuf::from(value);
        assert!(
            path.is_absolute(),
            "HS_REAL_ENGINE must be an absolute path"
        );
        let metadata = fs::metadata(&path)
            .unwrap_or_else(|error| panic!("read the staged engine {}: {error}", path.display()));
        assert!(
            metadata.is_file(),
            "the staged engine {} is not a file",
            path.display()
        );
        assert!(
            metadata.mode() & 0o111 != 0,
            "the staged engine {} is not executable",
            path.display()
        );
        return path;
    }
    build_engine(home)
}

fn build_engine(home: &Path) -> PathBuf {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the repository root")
        .to_path_buf();
    let manifest = repository.join("rust").join("Cargo.toml");
    assert!(
        manifest.is_file(),
        "the engine source is not available; set HS_REAL_ENGINE to a staged engine"
    );
    let target = home.join("build-target");
    fs::create_dir(&target).expect("create the private engine build directory");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700))
        .expect("make the engine build directory private");
    let metadata = fs::symlink_metadata(&target).expect("read the private engine build directory");
    assert_eq!(metadata.uid(), 0, "the build directory must be root owned");
    assert_eq!(
        metadata.mode() & 0o777,
        0o700,
        "the build directory must be private"
    );
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(cargo);
    command
        .args([
            "build",
            "--release",
            "--locked",
            "--bin",
            "hotspotshade",
            "--manifest-path",
        ])
        .arg(&manifest)
        .env("CARGO_TARGET_DIR", &target)
        /* The outer cargo run owns a jobserver whose descriptors this child
         * must not try to use. */
        .env_remove("CARGO_MAKEFLAGS")
        .env_remove("MAKEFLAGS")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let mut group = support::spawn_in_group(&mut command).expect("run cargo build for the engine");
    let status = group
        .wait_exit(Duration::from_secs(900))
        .expect("the real engine build finished within its budget");
    assert!(
        status.success(),
        "the real engine did not build: {status:?}"
    );
    let engine = target.join("release").join("hotspotshade");
    let metadata = fs::metadata(&engine)
        .unwrap_or_else(|error| panic!("read the built engine {}: {error}", engine.display()));
    assert!(metadata.is_file(), "the built engine is a file");
    engine
}

fn assert_root_directory(path: &Path) {
    let metadata = fs::symlink_metadata(path)
        .unwrap_or_else(|error| panic!("read the directory {}: {error}", path.display()));
    assert!(
        metadata.is_dir(),
        "{} must be a directory, not a symlink",
        path.display()
    );
    assert_eq!(
        metadata.uid(),
        0,
        "{} must be owned by root",
        path.display()
    );
    assert_eq!(
        metadata.mode() & 0o022,
        0,
        "{} must not be writable by another user",
        path.display()
    );
}

/* Stage the engine at the fixed packaged path with the modes the helper
 * validates. Every parent directory up to the root must be root owned and not
 * writable by another user, or the helper fails closed. */
fn stage_engine(source: &Path) {
    let source_metadata = fs::metadata(source)
        .unwrap_or_else(|error| panic!("read the engine {}: {error}", source.display()));
    assert!(source_metadata.is_file(), "the engine source is a file");
    assert_root_directory(Path::new("/opt"));
    assert_root_directory(Path::new(ENGINE_ROOT));
    assert_root_directory(Path::new(ENGINE_DIR));

    let copied = fs::copy(source, ENGINE).expect("stage the engine at the fixed path");
    assert_eq!(
        copied,
        source_metadata.len(),
        "the staged engine has the source length"
    );
    fs::set_permissions(ENGINE, fs::Permissions::from_mode(0o755))
        .expect("make the staged engine executable");

    let metadata = fs::metadata(ENGINE).expect("read the staged engine");
    assert!(metadata.is_file(), "the staged engine is a regular file");
    assert_eq!(metadata.uid(), 0, "the staged engine must be owned by root");
    assert_eq!(
        metadata.mode() & 0o022,
        0,
        "the staged engine must not be writable by another user"
    );
    assert!(
        metadata.mode() & 0o111 != 0,
        "the staged engine must be executable"
    );
}

fn prepare_engine_home() {
    let metadata = fs::symlink_metadata(HOME_DIR)
        .unwrap_or_else(|error| panic!("read the engine home: {error}"));
    assert!(metadata.is_dir(), "the engine home is a directory");
    assert_eq!(metadata.uid(), 0, "the engine home must be owned by root");
    assert_eq!(
        metadata.mode() & 0o777,
        0o700,
        "the engine home must be private"
    );
}

fn read_lines(pipe: impl Read + Send + 'static, sender: mpsc::Sender<String>) {
    thread::spawn(move || {
        for line in BufReader::new(pipe).lines().map_while(Result::ok) {
            if sender.send(line).is_err() {
                break;
            }
        }
    });
}

/* One real helper process. The helper runs in its own process group so a
 * failed assertion or a timeout can stop the helper and the engine it owns.
 * The group guard stops the whole group before it reaps the leader. */
struct HelperSession {
    group: ProcessGroup,
    lines: mpsc::Receiver<String>,
    errors: mpsc::Receiver<String>,
    stdout_log: Vec<String>,
    stderr_log: Vec<String>,
}

impl HelperSession {
    fn start() -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_hotspotshade-helper"));
        command
            .env("PKEXEC_UID", "1000")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut child = command.spawn().expect("start the real helper");
        let stdout = child.stdout.take().expect("the helper stdout");
        let stderr = child.stderr.take().expect("the helper stderr");
        let group = ProcessGroup::new(child).expect("record the helper process identity");
        let (line_sender, lines) = mpsc::channel();
        let (error_sender, errors) = mpsc::channel();
        read_lines(stdout, line_sender);
        read_lines(stderr, error_sender);
        Self {
            group,
            lines,
            errors,
            stdout_log: Vec::new(),
            stderr_log: Vec::new(),
        }
    }

    fn helper_pid(&self) -> u32 {
        self.group.id()
    }

    /* Write the request the Electron client writes. The secret travels on the
     * pipe only, never on a command line and never into a log. */
    fn send_request(&mut self) {
        let stdin = self.group.stdin_mut().expect("the helper stdin");
        write!(stdin, "HS1\n{SECRET}\n").expect("write the helper request");
        stdin.flush().expect("flush the helper request");
    }

    fn wait_for_line(&mut self, prefix: &str, timeout: Duration) -> String {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    self.stdout_log.push(line.clone());
                    if line.starts_with(prefix) {
                        return line;
                    }
                }
                Err(error) => {
                    self.drain_logs();
                    panic!(
                        "no {prefix} line from the helper within {timeout:?}: {error}\nhelper stderr:\n{}",
                        self.stderr_log.join("\n")
                    );
                }
            }
        }
    }

    fn drain_logs(&mut self) {
        while let Ok(line) = self.lines.try_recv() {
            self.stdout_log.push(line);
        }
        while let Ok(line) = self.errors.try_recv() {
            self.stderr_log.push(line);
        }
    }

    /* Closing the request pipe is what the Electron client does on Stop. The
     * helper drops the parent descriptor, and the engine stops itself. */
    fn close_request(&mut self) {
        drop(self.group.take_stdin());
    }

    /* The helper holds the write half of the engine liveness socketpair as its
     * only socket. Dropping it is what delivers end of file to the engine. */
    fn liveness_sockets(&self) -> Vec<String> {
        support::socket_descriptors(self.group.id()).expect("read the helper descriptors")
    }

    /* Prove that the engine leaves on its own liveness channel and not on the
     * helper SIGTERM.
     *
     * The helper sends SIGTERM no earlier than its source-defined grace after it sees
     * the closed request pipe, and it cannot see that before `closed_at`. So a
     * frozen helper cannot signal, and if the freeze lands before
     * `closed_at + grace` the SIGTERM cannot have been sent yet.
     *
     *   1. Note when the request pipe closes.
     *   2. Wait until the helper has released its liveness socket. From that
     *      point EOF can become visible to the engine.
     *   3. Freeze the helper with SIGSTOP and require that this happened
     *      inside the grace window. A late freeze fails as inconclusive; it
     *      never passes.
     *   4. Look at the engine once, after the freeze is confirmed, and require
     *      that this look is also inside the grace window. The engine got
     *      its EOF when the helper released the socket, so it may already be
     *      gone: a fast engine exits within milliseconds, before the SIGSTOP
     *      lands. That is the behavior under test, not a defect. Because the
     *      helper cannot send SIGTERM before `closed_at + grace`, an engine
     *      that is gone, or still alive, inside that window left (or is
     *      leaving) without a helper signal. A zombie counts as exited. This
     *      does not exclude every exit cause.
     *   5. Wait for the engine to exit while the helper is frozen if it has not
     *      yet. A frozen helper cannot signal during this wait.
     *   6. Resume the helper so it reaps the engine and reports its status.
     *
     * The only timing bound that can fail a correct run is the grace window
     * for the freeze and the engine look, and it fails closed. The engine wait
     * is long and does not decide the proof. An engine that exited before the
     * freeze is not an inconclusive result: nothing in that order can have
     * sent a signal. */
    fn close_and_prove_liveness_exit(&mut self, engine_pid: u32, engine_start_time: u64) {
        let grace = helper_eof_grace();
        let before = self.liveness_sockets();
        assert!(
            !before.is_empty(),
            "the helper holds the engine liveness socket before the stop"
        );
        assert!(
            !support::process_exited(engine_pid, engine_start_time)
                .expect("inconclusive: cannot inspect engine"),
            "inconclusive: engine exited before release"
        );
        let closed_at = Instant::now();
        self.close_request();
        loop {
            let held = self.liveness_sockets();
            if !held.iter().any(|socket| before.contains(socket)) {
                break;
            }
            if closed_at.elapsed() >= LIVENESS_RELEASE_BUDGET {
                self.drain_logs();
                panic!(
                    "the helper kept its liveness socket for {LIVENESS_RELEASE_BUDGET:?} after the request closed\nhelper stderr:\n{}",
                    self.stderr_log.join("\n")
                );
            }
            thread::sleep(Duration::from_millis(5));
        }
        self.group
            .pause_leader()
            .expect("freeze the helper before it can signal");
        let state = self
            .group
            .wait_leader_frozen(Duration::from_secs(2))
            .expect("the helper is frozen");
        let frozen_after = closed_at.elapsed();
        assert!(
            matches!(state, 'T' | 't'),
            "inconclusive: helper exited before it was frozen: {state}"
        );
        assert!(
            frozen_after < grace,
            "inconclusive: helper froze {frozen_after:?} after close, past {grace:?}"
        );
        /* The engine may already have left on the liveness EOF. Record which
         * order happened, and bound the look by the same grace window as the
         * freeze: both must precede the earliest possible helper SIGTERM. */
        let engine_gone_at_freeze = support::process_exited(engine_pid, engine_start_time)
            .expect("inconclusive: cannot inspect engine");
        let observed_after = closed_at.elapsed();
        assert!(
            observed_after < grace,
            "inconclusive: engine inspected {observed_after:?} after close, past {grace:?}"
        );
        assert!(
            matches!(self.group.wait_leader_frozen(Duration::ZERO), Ok('T' | 't')),
            "inconclusive: helper was not frozen when the engine was inspected"
        );
        /* A frozen helper cannot send a signal during this wait. */
        wait_for_process_exit(engine_pid, engine_start_time, ENGINE_LIVENESS_EXIT_BUDGET);
        assert!(
            matches!(self.group.wait_leader_frozen(Duration::ZERO), Ok('T' | 't')),
            "inconclusive: helper did not remain frozen"
        );
        eprintln!(
            "liveness exit proof: helper state {state} {frozen_after:?} after the request closed (SIGTERM grace {grace:?}); the engine was {} when the helper froze and left with the helper frozen",
            if engine_gone_at_freeze { "already gone" } else { "still alive" }
        );
        if state != 'Z' {
            self.group
                .resume_leader()
                .expect("resume the helper after the engine left");
        }
    }

    fn wait_exit(&mut self, timeout: Duration) -> ExitStatus {
        match self.group.wait_exit(timeout) {
            Ok(status) => {
                /* Give the pipe readers a moment to reach end of file. */
                thread::sleep(Duration::from_millis(100));
                self.drain_logs();
                status
            }
            Err(error) => {
                self.drain_logs();
                panic!(
                    "the helper did not exit cleanly within {timeout:?}: {error}\nhelper stderr:\n{}",
                    self.stderr_log.join("\n")
                );
            }
        }
    }

    fn stderr_text(&self) -> String {
        self.stderr_log.join("\n")
    }

    fn assert_no_secret_in_output(&mut self) {
        self.drain_logs();
        for line in self.stdout_log.iter().chain(self.stderr_log.iter()) {
            assert!(
                !line.contains(SECRET),
                "the helper printed the per-launch secret"
            );
        }
    }
}

struct Response {
    code: u16,
    head: String,
    body: String,
}

fn http_status(port: u16, authorization: Option<&str>) -> Response {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&address, HTTP_SOCKET_TIMEOUT)
        .expect("connect to the loopback GUI");
    stream
        .set_read_timeout(Some(HTTP_SOCKET_TIMEOUT))
        .expect("set the read timeout");
    stream
        .set_write_timeout(Some(HTTP_SOCKET_TIMEOUT))
        .expect("set the write timeout");
    let auth = match authorization {
        Some(value) => format!("Authorization: Bearer {value}\r\n"),
        None => String::new(),
    };
    let request = format!(
        "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{auth}Connection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .expect("write the loopback request");

    let deadline = Instant::now() + HTTP_RESPONSE_BUDGET;
    let mut response = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        assert!(
            Instant::now() < deadline,
            "the loopback response did not end within its budget"
        );
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                response.extend_from_slice(&buffer[..count]);
                assert!(
                    response.len() <= 1 << 20,
                    "the loopback response is too large"
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => panic!("read the loopback response: {error}"),
        }
    }
    let text = String::from_utf8(response).expect("the loopback response is text");
    let split = text
        .find("\r\n\r\n")
        .unwrap_or_else(|| panic!("the loopback response has no header end: {text:.200}"));
    let (head, body) = text.split_at(split);
    let body = &body[4..];
    let code = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("the loopback response has no status code: {head}"));
    Response {
        code,
        head: head.to_owned(),
        body: body.to_owned(),
    }
}

fn parse_port(line: &str) -> u16 {
    let port = line
        .split_whitespace()
        .nth(1)
        .unwrap_or_else(|| panic!("the helper port line has no port: {line}"))
        .parse::<u16>()
        .unwrap_or_else(|_| panic!("the helper port line is not numeric: {line}"));
    assert_ne!(port, 0, "the helper reported a zero port");
    port
}

fn parse_state(text: &str) -> (u32, u64) {
    let mut lines = text.lines();
    assert_eq!(
        lines.next(),
        Some("HS_ENGINE 2"),
        "the engine state record format"
    );
    let boot = lines.next().expect("the engine state has a boot line");
    assert!(
        boot.len() == 41 && boot.starts_with("BOOT "),
        "the engine state has a boot id: {boot}"
    );
    let namespace = lines.next().expect("the engine state has a namespace line");
    assert!(
        namespace.starts_with("NS "),
        "the engine state has a namespace: {namespace}"
    );
    let mut parts = lines
        .next()
        .expect("the engine state has a process line")
        .split_whitespace();
    assert_eq!(
        parts.next(),
        Some("ENGINE"),
        "the engine state names an engine, not a pending start"
    );
    let pid = parts
        .next()
        .expect("the engine state has a process id")
        .parse::<u32>()
        .expect("the engine state process id is numeric");
    let start_time = parts
        .next()
        .expect("the engine state has a start time")
        .parse::<u64>()
        .expect("the engine state start time is numeric");
    assert!(
        parts.next().is_none(),
        "the engine state has no extra fields"
    );
    assert!(
        lines.next().is_none(),
        "the engine state has no extra lines"
    );
    (pid, start_time)
}

fn read_engine_state() -> (u32, u64) {
    let metadata = fs::metadata(STATE).expect("read the engine state record");
    assert_eq!(metadata.uid(), 0, "the engine state must be owned by root");
    assert_eq!(
        metadata.mode() & 0o777,
        0o600,
        "the engine state must be private"
    );
    let text = fs::read_to_string(STATE).expect("read the engine state text");
    parse_state(&text)
}

fn wait_for_process_exit(pid: u32, start_time: u64, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        if support::process_exited(pid, start_time)
            .expect("inconclusive: cannot inspect engine process")
        {
            return;
        }
        if Instant::now() >= deadline {
            panic!("the engine process {pid} is still alive");
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn read_command_line(pid: u32) -> Vec<String> {
    let bytes = fs::read(format!("/proc/{pid}/cmdline")).expect("read the engine command line");
    bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect()
}

/* Return the port file path from the engine command line after proving the
 * secret travels on a descriptor only. */
fn assert_engine_command_line(pid: u32) -> String {
    let args = read_command_line(pid);
    assert!(
        args.iter().any(|arg| arg == "gui"),
        "the helper starts the engine in GUI mode"
    );
    assert!(
        !args.iter().any(|arg| arg.contains(SECRET)),
        "the engine command line must not carry the per-launch secret"
    );
    for (flag, value) in [("--token-fd", "3"), ("--parent-fd", "4"), ("--port", "0")] {
        let position = args
            .iter()
            .position(|arg| arg == flag)
            .unwrap_or_else(|| panic!("the engine command line has no {flag}"));
        assert_eq!(
            args.get(position + 1).map(String::as_str),
            Some(value),
            "the engine {flag} value"
        );
    }
    assert!(
        !args.iter().any(|arg| arg == "--demo"),
        "the helper starts the real backend, not the demo backend"
    );
    let position = args
        .iter()
        .position(|arg| arg == "--port-file")
        .expect("the engine command line has a port file");
    args.get(position + 1)
        .cloned()
        .expect("the engine port file path")
}

/* The GUI binds 127.0.0.1 only. /proc/net/tcp holds IPv4 listeners as
 * LITTLE_ENDIAN:PORT in hex, so loopback is 0100007F. */
fn assert_loopback_listener(port: u16) {
    let table = fs::read_to_string("/proc/net/tcp").expect("read the IPv4 socket table");
    let mut listening = 0;
    for line in table.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let Some((address, local_port)) = fields[1].split_once(':') else {
            continue;
        };
        if u16::from_str_radix(local_port, 16) != Ok(port) {
            continue;
        }
        if fields[3] != "0A" {
            continue;
        }
        listening += 1;
        assert_eq!(
            address, "0100007F",
            "the GUI listener must bind 127.0.0.1 only"
        );
    }
    assert_eq!(listening, 1, "the GUI has one loopback listener on {port}");
    let table6 = fs::read_to_string("/proc/net/tcp6").expect("read the IPv6 socket table");
    for line in table6.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 4 && fields[3] == "0A" {
            if let Some((_, local_port)) = fields[1].split_once(':') {
                assert_ne!(
                    u16::from_str_radix(local_port, 16),
                    Ok(port),
                    "unexpected IPv6 listener on GUI port"
                );
            }
        }
    }
}

fn assert_no_engine_process() {
    assert!(
        !support::engine_alive().expect("prove that no engine is alive"),
        "an engine process is still alive"
    );
}

fn assert_authenticated_status(port: u16) {
    let response = http_status(port, Some(SECRET));
    assert_eq!(
        response.code, 200,
        "the authenticated status is accepted: {}",
        response.head
    );
    let head = response.head.to_ascii_lowercase();
    assert!(
        head.contains("content-type: application/json"),
        "the status answer is JSON: {}",
        response.head
    );
    assert!(
        !response.body.contains(SECRET),
        "the status answer must not hold the per-launch secret"
    );
    assert!(
        response.body.contains("\"demo\":false"),
        "the status comes from the real backend: {}",
        response.body
    );
    assert!(
        response.body.contains("\"running\":false"),
        "no tunnel is running: {}",
        response.body
    );
    assert!(
        response
            .body
            .contains(&format!("\"os\":\"{}\"", env::consts::OS)),
        "the status names the platform: {}",
        response.body
    );
}

fn assert_rejected_status(port: u16, authorization: Option<&str>, label: &str) {
    let response = http_status(port, authorization);
    assert_eq!(
        response.code, 401,
        "a {label} request must be rejected: {}",
        response.head
    );
    assert!(
        response.body.contains("\"error\":\"unauthorized\""),
        "a {label} request gets the fixed refusal: {}",
        response.body
    );
    assert!(
        !response.body.contains(SECRET),
        "the refusal must not echo the secret"
    );
}

/* One start, status check, clean stop, and cleanup. */
fn run_engine_lifecycle() {
    let mut session = HelperSession::start();
    let helper_pid = session.helper_pid();
    session.send_request();

    let ready = session.wait_for_line("HS_READY", Duration::from_secs(10));
    assert_eq!(ready.trim(), "HS_READY", "the helper reports readiness");
    let port_line = session.wait_for_line("HS_PORT ", Duration::from_secs(30));
    let port = parse_port(&port_line);

    let (engine_pid, engine_start_time) = read_engine_state();
    let port_path = assert_engine_command_line(engine_pid);

    /* The helper removes its private port directory before it reports the
     * port. Only the helper temporary directory for this pid can remain. */
    assert!(
        !Path::new(&port_path).exists(),
        "the helper removes the engine port file"
    );
    assert!(
        Path::new(&port_path)
            .parent()
            .is_some_and(|directory| !directory.exists()),
        "the helper removes its private temporary directory"
    );
    let leftovers: Vec<_> = fs::read_dir("/tmp")
        .expect("read the temporary directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(&format!("hotspotshade-helper-{helper_pid}-")))
        })
        .collect();
    assert!(
        leftovers.is_empty(),
        "the helper leaves no temporary directory: {leftovers:?}"
    );

    assert_loopback_listener(port);
    assert_authenticated_status(port);
    assert_rejected_status(port, Some(WRONG_SECRET), "wrong secret");
    assert_rejected_status(port, None, "missing secret");
    /* A rejected request must not disturb the live service. */
    assert_authenticated_status(port);

    /* Stop the way the Electron client does: close the request channel. The
     * helper drops the parent descriptor. Prove that the engine then leaves on
     * that liveness channel, not on the later helper SIGTERM, then let the
     * helper finish. */
    session.close_and_prove_liveness_exit(engine_pid, engine_start_time);
    let status = session.wait_exit(Duration::from_secs(30));
    assert_eq!(
        status.code(),
        Some(0),
        "the helper stops cleanly\nhelper stderr:\n{}",
        session.stderr_text()
    );
    assert!(
        !session
            .stdout_log
            .iter()
            .any(|line| line.contains("HS_STOP_TIMEOUT")),
        "the helper reported no stop timeout"
    );
    session.assert_no_secret_in_output();

    assert!(
        !Path::new(STATE).exists(),
        "the helper removes the engine state record"
    );
    wait_for_process_exit(engine_pid, engine_start_time, Duration::from_secs(20));
    assert_no_engine_process();
}

#[test]
fn the_real_engine_serves_authenticated_loopback_status_and_stops_cleanly() {
    if !support::enabled() {
        eprintln!(
            "skipping the real engine lifecycle test; it needs HS_HELPER_INTEGRATION=1, root, and a disposable container"
        );
        return;
    }
    let _reservation = support::reserve();
    assert_public_vector();
    let mut sandbox = Sandbox::create().expect("create the fixed test roots exclusively");
    let engine = engine_source(sandbox.home());
    stage_engine(&engine);
    prepare_engine_home();

    /* The helper refuses a second start while the first helper lives. The fake
     * engine test covers that guard. Here the real engine proves the full
     * path. */
    run_engine_lifecycle();

    /* A second real start proves the first stop released the helper lock and
     * removed the state record. */
    run_engine_lifecycle();

    sandbox.cleanup().expect("remove the fixed test roots");
}
