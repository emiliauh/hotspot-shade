//! The Linux pairing handoff between the user engine and the root engine.
//!
//! The Linux app runs the engine as the signed-in user with its handoff socket
//! on descriptor 0. The pkexec helper later passes that socket to the root
//! engine as descriptor 5 with `--credentials-fd 5`. These tests run the real
//! engine as the test user. They create no tunnel device, set no route, and
//! need no source device or root.
//!
//! The test also runs on macOS, where the same descriptor options exist and
//! the user engine routes `POST /api/pairing/handoff` to its backend, as
//! on Linux.
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use hotspotshade::credential_handoff::write_handoff;
use hotspotshade::pairing::{Identity, PhoneCredentials};

const TOKEN: &str = "public-test-linux-handoff-token";
const SECRET: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

fn private_directory(label: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "hotspotshade-linux-handoff-{}-{}-{}",
        label,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).expect("private test directory");
    directory
}

fn request(port: u16, method: &str, path: &str) -> String {
    request_with_body(port, method, path, if method == "POST" { "{}" } else { "" })
}

fn request_with_body(port: u16, method: &str, path: &str, body: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("engine connection");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let content = if method == "POST" {
        format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        )
    } else {
        String::new()
    };
    stream
        .write_all(
            format!(
                "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {SECRET}\r\n{content}Connection: close\r\n\r\n{body}"
            )
            .as_bytes(),
        )
        .unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).unwrap();
    reply
}

/// Start the engine with the token on descriptor 3 and `extra` descriptors
/// placed at fixed numbers in the child, as the app and the helper do.
fn spawn_engine(
    directory: &Path,
    extra_args: &[&str],
    stdin: Option<RawFd>,
    credentials: Option<RawFd>,
) -> Child {
    let engine = env!("CARGO_BIN_EXE_hotspotshade");
    let (token_child, mut token_parent) = UnixStream::pair().unwrap();
    token_parent
        .write_all(format!("{SECRET}\n").as_bytes())
        .unwrap();
    drop(token_parent);
    let token_fd = token_child.as_raw_fd();
    let port_file = directory.join("port");
    let mut command = Command::new(engine);
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
        ])
        .args(extra_args)
        .env("HOME", directory.join("home"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            std::fs::File::create(directory.join("stderr")).unwrap(),
        ));
    unsafe {
        command.pre_exec(move || {
            // Lift every source above the targets first, so one dup2 cannot
            // replace a source that another dup2 still needs.
            let lift = |fd: RawFd| {
                let lifted = libc::fcntl(fd, libc::F_DUPFD, 100);
                if lifted < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(lifted)
                }
            };
            let token = lift(token_fd)?;
            let stdin = stdin.map(lift).transpose()?;
            let credentials = credentials.map(lift).transpose()?;
            for (source, target) in [(Some(token), 3), (stdin, 0), (credentials, 5)] {
                if let Some(fd) = source {
                    if libc::dup2(fd, target) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
            }
            Ok(())
        });
    }
    let child = command.spawn().expect("spawn the engine");
    drop(token_child);
    child
}

fn wait_for_port(child: &mut Child, directory: &Path) -> Option<u16> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(text) = std::fs::read_to_string(directory.join("port")) {
            if let Ok(port) = text.trim().parse::<u16>() {
                return Some(port);
            }
        }
        if let Ok(Some(_)) = child.try_wait() {
            return None;
        }
        if Instant::now() > deadline {
            let stderr = std::fs::read_to_string(directory.join("stderr")).unwrap_or_default();
            let _ = child.kill();
            panic!("the engine did not publish its port: {stderr}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// SIGTERM uses the engine's normal cleanup path. These engines start no
/// tunnel, so there is nothing to remove.
fn stop_engine(mut child: Child, directory: &Path) {
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(10) {
        if let Ok(Some(_)) = child.try_wait() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(directory);
}

fn exit_within(child: &mut Child, limit: Duration) -> Option<std::process::ExitStatus> {
    let started = Instant::now();
    while started.elapsed() < limit {
        if let Ok(Some(status)) = child.try_wait() {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

#[test]
fn a_user_engine_with_a_stdin_handoff_serves_status_and_refuses_an_unpaired_handoff() {
    let directory = private_directory("user");
    let (engine_end, app_end) = UnixStream::pair().unwrap();
    let mut child = spawn_engine(
        &directory,
        &["--handoff-fd", "0"],
        Some(engine_end.as_raw_fd()),
        None,
    );
    drop(engine_end);
    let port = wait_for_port(&mut child, &directory).expect("the user engine starts");
    let status = request(port, "GET", "/api/status");
    assert!(status.contains("\"paired\":false"), "{status}");
    // The user engine read its identity once at launch from its own HOME.
    assert!(directory
        .join("home/Library/Application Support/hotspotshade/identity.key")
        .exists());
    let answer = request(port, "POST", "/api/pairing/handoff");
    assert!(answer.contains(" 409 "), "{answer}");
    // Both platforms route the handoff to the user engine backend. An
    // unpaired engine refuses it with its own code, never the trait default.
    assert!(answer.contains("not_paired"), "{answer}");
    assert!(!answer.contains("handoff_unsupported"), "{answer}");
    // Nothing was written to the handoff socket.
    app_end.set_nonblocking(true).unwrap();
    let mut byte = [0u8; 1];
    assert!((&app_end).read(&mut byte).is_err());
    stop_engine(child, &directory);
}

#[test]
fn a_root_style_engine_imports_the_newest_frame_and_never_returns_the_token() {
    let directory = private_directory("import");
    let (engine_end, user_end) = UnixStream::pair().unwrap();
    let identity = Identity::from_bytes([0x52; 32]);
    let old = PhoneCredentials {
        host: Ipv4Addr::new(192, 0, 2, 1),
        port: 18080,
        token: "public-older-token".into(),
    };
    let new = PhoneCredentials {
        host: Ipv4Addr::new(192, 0, 2, 1),
        port: 18081,
        token: TOKEN.into(),
    };
    write_handoff(user_end.as_raw_fd(), &identity, &old).unwrap();
    write_handoff(user_end.as_raw_fd(), &identity, &new).unwrap();
    let mut child = spawn_engine(
        &directory,
        &["--credentials-fd", "5"],
        None,
        Some(engine_end.as_raw_fd()),
    );
    drop(engine_end);
    let port = wait_for_port(&mut child, &directory).expect("the importing engine starts");
    let status = request(port, "GET", "/api/status");
    assert!(status.contains("\"paired\":true"), "{status}");
    assert!(status.contains("\"phone_port\":18081"), "{status}");
    assert!(!status.contains(TOKEN));
    assert!(!status.contains("public-older-token"));
    // The importing engine never exports a second handoff.
    let answer = request(port, "POST", "/api/pairing/handoff");
    assert!(answer.contains(" 409 "), "{answer}");
    assert!(!answer.contains(TOKEN));
    // An importing engine starts only the tunnel. A SOCKS5 listener would run
    // as root without its own authorization, so it is refused.
    let refused = request_with_body(
        port,
        "POST",
        "/api/start",
        r#"{"mode":"socks5","options":{"host":"127.0.0.1","port":1080}}"#,
    );
    assert!(
        refused.contains("The protected engine starts only the tunnel."),
        "{refused}"
    );
    assert!(!request(port, "GET", "/api/status").contains("\"running\":true"));
    // The imported identity replaced the HOME key. No root HOME key exists.
    assert!(!directory
        .join("home/Library/Application Support/hotspotshade/identity.key")
        .exists());
    drop(user_end);
    stop_engine(child, &directory);
}

#[test]
fn an_empty_credentials_socket_is_a_failed_launch() {
    let directory = private_directory("empty");
    let (engine_end, _user_end) = UnixStream::pair().unwrap();
    let mut child = spawn_engine(
        &directory,
        &["--credentials-fd", "5"],
        None,
        Some(engine_end.as_raw_fd()),
    );
    drop(engine_end);
    let status = exit_within(&mut child, Duration::from_secs(10)).expect("the engine exits");
    assert!(!status.success());
    assert!(
        !directory.join("port").exists(),
        "no listener was published"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn a_pairing_descriptor_cannot_be_the_token_descriptor() {
    let directory = private_directory("shared");
    let mut child = spawn_engine(&directory, &["--credentials-fd", "3"], None, None);
    let status = exit_within(&mut child, Duration::from_secs(10)).expect("the engine exits");
    assert!(!status.success());
    let stderr = std::fs::read_to_string(directory.join("stderr")).unwrap_or_default();
    assert!(stderr.contains("separate descriptor"), "{stderr}");
    let _ = std::fs::remove_dir_all(&directory);
}

/// Run one launch that must fail before the listener binds. Returns stderr.
fn refused_launch(label: &str, extra_args: &[&str], stdin: Option<RawFd>) -> String {
    let directory = private_directory(label);
    let mut child = spawn_engine(&directory, extra_args, stdin, None);
    let status = exit_within(&mut child, Duration::from_secs(10)).expect("the engine exits");
    assert!(!status.success());
    assert!(
        !directory.join("port").exists(),
        "a refused launch publishes no listener"
    );
    let stderr = std::fs::read_to_string(directory.join("stderr")).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&directory);
    stderr
}

#[test]
fn a_handoff_descriptor_cannot_be_the_token_or_parent_descriptor() {
    let stderr = refused_launch("handoff-token", &["--handoff-fd", "3"], None);
    assert!(stderr.contains("separate descriptor"), "{stderr}");
    let (engine_end, _app_end) = UnixStream::pair().unwrap();
    let stderr = refused_launch(
        "handoff-parent",
        &["--handoff-fd", "0", "--parent-fd", "0"],
        Some(engine_end.as_raw_fd()),
    );
    assert!(stderr.contains("separate descriptor"), "{stderr}");
}

#[test]
fn a_named_parent_descriptor_that_is_not_open_fails_before_the_listener() {
    let stderr = refused_launch("parent-closed", &["--parent-fd", "63"], None);
    assert!(stderr.contains("parent descriptor is not open"), "{stderr}");
    assert!(!stderr.contains("63"), "{stderr}");
}

#[test]
fn a_named_handoff_descriptor_that_is_not_open_fails_before_the_listener() {
    let stderr = refused_launch("handoff-closed", &["--handoff-fd", "63"], None);
    assert!(
        stderr.contains("pairing handoff descriptor is not open"),
        "{stderr}"
    );
}

/// The macOS app passes the pairing handoff as one end of a Unix socket pair.
/// A pipe in that slot is a failed launch.
#[cfg(target_os = "macos")]
#[test]
fn a_macos_handoff_descriptor_must_be_a_socket() {
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let stderr = refused_launch("handoff-pipe", &["--handoff-fd", "0"], Some(fds[0]));
    unsafe {
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
    assert!(
        stderr.contains("pairing handoff descriptor is not a socket"),
        "{stderr}"
    );
}
