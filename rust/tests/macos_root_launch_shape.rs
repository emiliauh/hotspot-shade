//! The root engine starts in the exact shape that the protected helper uses.
//!
//! `RootEngineLauncher.swift` spawns the engine with the per-launch secret on
//! descriptor 3, the liveness pipe on descriptor 4, the start-exclusion lock
//! on descriptor 5 (with its four environment values), and the user engine's
//! pairing handoff socket on descriptor 6. Its environment is exactly `HOME`,
//! `PATH`, `LC_ALL`, and the exclusion values, and descriptors 0 to 2 are the
//! helper's own. The user engine keeps its end of the handoff socket open.
//!
//! These tests run the real engine binary in that shape as the test user. They
//! create no tunnel device, set no route, and never write a grant, so the
//! engine cannot change a route. Set `HOTSPOTSHADE_LAUNCH_SHAPE_ENGINE` to run
//! another engine build, such as an installed one, in the same shape.
#![cfg(target_os = "macos")]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use hotspotshade::credential_handoff::write_handoff;
use hotspotshade::pairing::{Identity, PhoneCredentials};

const SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const TOKEN: &str = "public-launch-shape-token";

fn engine_path() -> String {
    std::env::var("HOTSPOTSHADE_LAUNCH_SHAPE_ENGINE")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_hotspotshade").to_string())
}

fn private_directory(label: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "hs-shape-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn pipe() -> (RawFd, RawFd) {
    let mut fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    for fd in fds {
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    (fds[0], fds[1])
}

fn write_all_fd(descriptor: RawFd, bytes: &[u8]) {
    let mut buffer = bytes;
    while !buffer.is_empty() {
        let count = unsafe { libc::write(descriptor, buffer.as_ptr().cast(), buffer.len()) };
        assert!(count > 0);
        buffer = &buffer[count as usize..];
    }
}

/// One spawned engine in the helper launch shape and what the test keeps.
struct ShapedEngine {
    child: Child,
    parent_write: RawFd,
    directory: PathBuf,
    stderr: PathBuf,
    port_file: PathBuf,
    grant_file: PathBuf,
    // The user engine keeps its handoff end open while the root engine runs.
    _user_end: UnixStream,
}

impl ShapedEngine {
    fn wait_for_port(&mut self, limit: Duration) -> Result<u16, String> {
        let deadline = Instant::now() + limit;
        loop {
            if let Ok(text) = std::fs::read_to_string(&self.port_file) {
                if let Ok(port) = text.trim().parse::<u16>() {
                    return Ok(port);
                }
            }
            if let Ok(Some(status)) = self.child.try_wait() {
                let stderr = std::fs::read_to_string(&self.stderr).unwrap_or_default();
                return Err(format!(
                    "exited before the port: {status}; stderr: {stderr}"
                ));
            }
            if Instant::now() > deadline {
                return Err("no port before the deadline".into());
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn stderr_text(&self) -> String {
        std::fs::read_to_string(&self.stderr).unwrap_or_default()
    }

    /// The helper's normal stop: close the parent pipe, then SIGTERM.
    fn stop(mut self) -> std::process::ExitStatus {
        unsafe {
            libc::close(self.parent_write);
            libc::kill(self.child.id() as i32, libc::SIGTERM);
        }
        let started = Instant::now();
        let status = loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                break status;
            }
            if started.elapsed() > Duration::from_secs(20) {
                let _ = self.child.kill();
                panic!("the engine did not stop");
            }
            std::thread::sleep(Duration::from_millis(25));
        };
        let _ = std::fs::remove_dir_all(&self.directory);
        status
    }
}

/// What the handoff socket carries when the root engine starts.
enum Frame {
    /// One frame from the user engine, written through the real writer.
    Pairing(PhoneCredentials),
    /// Nothing was written.
    Empty,
}

/// How the launcher places the descriptors in the child.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Layout {
    /// Every source is moved above the targets before it is duplicated, as the
    /// fixed `RootEngineLauncher` does.
    Fixed,
    /// The file action order of the 2026-11-06 release candidate, with the
    /// XPC credentials descriptor on number 3 in the helper. The helper
    /// receives that descriptor before it creates its pipes, so a fresh
    /// helper process gets a low number. `dup2(token, 3)` then replaces it,
    /// `dup2(3, 6)` copies the token pipe to 6, and `close(3)` removes the
    /// token descriptor.
    OldOrderCredentialsOnThree,
}

fn spawn_root_shape(label: &str, frame: Frame) -> ShapedEngine {
    spawn_root_shape_with(label, frame, Layout::Fixed)
}

fn spawn_root_shape_with(label: &str, frame: Frame, layout: Layout) -> ShapedEngine {
    let directory = private_directory(label);
    // The helper's engine HOME is a fresh, empty root-owned directory.
    let home = directory.join("home");
    std::fs::create_dir(&home).unwrap();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
    let runtime = directory.join("run");
    std::fs::create_dir(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    let port_file = runtime.join("port");
    let grant_file = runtime.join("tunnel-grant");
    let stderr = directory.join("stderr");

    // Descriptor 5: a locked start-exclusion file, as the helper passes it.
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC)
        .open(directory.join("start-exclusion"))
        .unwrap();
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) },
        0
    );
    let lock_meta = lock.metadata().unwrap();

    // Descriptor 6: the app's end of the user engine's handoff socket pair.
    let (user_end, app_end) = UnixStream::pair().unwrap();
    if let Frame::Pairing(credentials) = &frame {
        let identity = Identity::from_bytes([0x37; 32]);
        write_handoff(user_end.as_raw_fd(), &identity, credentials).expect("handoff frame");
    }
    let app_fd = app_end.into_raw_fd();

    let (token_read, token_write) = pipe();
    write_all_fd(token_write, format!("{SECRET}\n").as_bytes());
    unsafe { libc::close(token_write) };
    let (parent_read, parent_write) = pipe();

    let error_handle = std::fs::File::create(&stderr).unwrap();
    let mut command = Command::new(engine_path());
    command
        .args([
            "gui",
            "--no-open",
            "--port",
            "0",
            "--port-file",
            port_file.to_str().unwrap(),
            "--token-fd",
            "3",
            "--parent-fd",
            "4",
            "--grant-file",
            grant_file.to_str().unwrap(),
            "--credentials-fd",
            "6",
        ])
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LC_ALL", "C")
        .env("HOTSPOTSHADE_START_EXCLUSION_FD", "5")
        .env("HOTSPOTSHADE_START_EXCLUSION_VERSION", "1")
        .env(
            "HOTSPOTSHADE_START_EXCLUSION_DEVICE",
            lock_meta.dev().to_string(),
        )
        .env(
            "HOTSPOTSHADE_START_EXCLUSION_INODE",
            lock_meta.ino().to_string(),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(error_handle));
    let lock_fd = lock.as_raw_fd();
    unsafe {
        command.pre_exec(move || {
            if layout == Layout::OldOrderCredentialsOnThree {
                // Put the credentials on 3, as the XPC descriptor was in the
                // helper, then replay the old action list in its order.
                if libc::dup2(app_fd, 3) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let token = libc::fcntl(token_read, libc::F_DUPFD, 20);
                let parent = libc::fcntl(parent_read, libc::F_DUPFD, 20);
                let lock = libc::fcntl(lock_fd, libc::F_DUPFD, 20);
                for (source, target) in [(token, 3), (parent, 4)] {
                    libc::dup2(source, target);
                }
                libc::close(token);
                libc::close(parent);
                libc::dup2(3, 6);
                libc::close(3);
                libc::dup2(lock, 5);
                libc::close(lock);
                return Ok(());
            }
            // Move every source above the targets first, so no dup2 lands
            // on a source that a later dup2 still needs.
            let mut moved = [0; 4];
            for (index, fd) in [token_read, parent_read, lock_fd, app_fd]
                .iter()
                .enumerate()
            {
                moved[index] = libc::fcntl(*fd, libc::F_DUPFD, 20);
                if moved[index] < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            for (source, target) in moved.iter().zip([3, 4, 5, 6]) {
                if libc::dup2(*source, target) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                libc::close(*source);
            }
            Ok(())
        });
    }
    let child = command.spawn().expect("spawn the engine");
    unsafe {
        libc::close(token_read);
        libc::close(parent_read);
        libc::close(app_fd);
    }
    drop(lock);
    ShapedEngine {
        child,
        parent_write,
        directory,
        stderr,
        port_file,
        grant_file,
        _user_end: user_end,
    }
}

fn request(port: u16, method: &str, path: &str, body: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .write_all(
            format!(
                "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {SECRET}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).unwrap();
    reply
}

fn paired_credentials() -> PhoneCredentials {
    PhoneCredentials {
        host: Ipv4Addr::new(172, 20, 10, 1),
        port: 18080,
        token: TOKEN.into(),
    }
}

#[test]
fn a_helper_shaped_engine_imports_the_pairing_publishes_its_port_and_stops_cleanly() {
    let mut engine = spawn_root_shape("ok", Frame::Pairing(paired_credentials()));
    let port = match engine.wait_for_port(Duration::from_secs(10)) {
        Ok(port) => port,
        Err(error) => panic!("the helper-shaped launch failed: {error}"),
    };
    let status = request(port, "GET", "/api/status", "");
    assert!(status.contains("\"paired\":true"), "{status}");
    assert!(!status.contains(TOKEN), "{status}");
    // The engine is still alive after the app's status check, which is when
    // the app asks for the administrator authorization.
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        engine.child.try_wait().unwrap().is_none(),
        "{}",
        engine.stderr_text()
    );
    assert!(!engine.grant_file.exists());
    let status = engine.stop();
    assert!(status.success(), "a clean stop exits zero: {status}");
}

#[test]
fn an_empty_handoff_fails_with_one_fixed_reason_line() {
    let mut engine = spawn_root_shape("empty", Frame::Empty);
    let error = engine
        .wait_for_port(Duration::from_secs(10))
        .expect_err("an empty handoff must fail the launch");
    assert!(
        engine
            .stderr_text()
            .contains("hotspotshade-start-failure: credentials_handoff_invalid"),
        "{error}"
    );
    let _ = engine.stop();
}

#[test]
fn the_old_descriptor_order_put_the_token_pipe_on_the_credentials_number() {
    // This is the launch that failed on 2026-11-06: the engine exits before it
    // publishes a port, so the helper never wrote a grant and no route
    // changed. The engine now names the cause with one fixed reason.
    let mut engine = spawn_root_shape_with(
        "old-order",
        Frame::Pairing(paired_credentials()),
        Layout::OldOrderCredentialsOnThree,
    );
    let error = engine
        .wait_for_port(Duration::from_secs(10))
        .expect_err("the old descriptor order must fail the launch");
    let stderr = engine.stderr_text();
    assert!(
        stderr.contains("hotspotshade-start-failure: credentials_descriptor_invalid"),
        "{error}"
    );
    assert!(!stderr.contains(TOKEN), "{stderr}");
    assert!(!engine.grant_file.exists());
    let _ = engine.stop();
}
