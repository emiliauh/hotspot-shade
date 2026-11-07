//! The root engine imports one pairing handoff from a user-owned engine.
//!
//! This test starts the real engine as the test user with a private
//! credentials descriptor. It creates no tunnel device, sets no route, and
//! needs no source device. It proves that the imported identity and
//! credentials reach the status answer, and that the token does not. It also
//! proves that an imported engine refuses phone and tun starts when the helper
//! passed no grant path, before any route or helper is involved.
#![cfg(target_os = "macos")]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::os::fd::{IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use hotspotshade::credential_handoff::{read_handoff, write_handoff};
use hotspotshade::pairing::{Identity, PhoneCredentials};

const TOKEN: &str = "public-test-handoff-token";
const SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn pipe() -> (RawFd, RawFd) {
    let mut fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    (fds[0], fds[1])
}

fn write_all_fd(descriptor: RawFd, bytes: &[u8]) {
    let mut buffer = bytes;
    while !buffer.is_empty() {
        let count = unsafe {
            libc::write(
                descriptor,
                buffer.as_ptr().cast(),
                buffer.len() as libc::size_t,
            )
        };
        assert!(count > 0);
        buffer = &buffer[count as usize..];
    }
}

fn get_status(port: u16, secret: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("status connection");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .write_all(
            format!(
                "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {secret}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).unwrap();
    let text = String::from_utf8_lossy(&bytes).to_string();
    text.split("\r\n\r\n").nth(1).unwrap_or("").to_string()
}

fn post_request(port: u16, path: &str, body: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("request connection");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .write_all(
            format!(
                "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {SECRET}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .unwrap();
    let mut reply = String::new();
    stream.read_to_string(&mut reply).unwrap();
    reply
}

/// Start the real engine as the test user with a private credentials
/// descriptor. `pass_grant_path` selects whether the helper-style
/// `--grant-file` option is present.
fn spawn_engine(label: &str, pass_grant_path: bool) -> (Child, u16, PathBuf, PathBuf) {
    let engine = env!("CARGO_BIN_EXE_hotspotshade");
    let identity = Identity::from_bytes([0x42; 32]);
    let credentials = PhoneCredentials {
        host: Ipv4Addr::new(172, 20, 10, 1),
        port: 18080,
        token: TOKEN.into(),
    };
    // The macOS app passes one end of a Unix socket pair, and the root engine
    // refuses any other descriptor kind for its credentials.
    let (credential_writer, credential_reader) = UnixStream::pair().unwrap();
    let (credential_write, credential_read) = (
        credential_writer.into_raw_fd(),
        credential_reader.into_raw_fd(),
    );
    write_handoff(credential_write, &identity, &credentials).expect("write the handoff");
    unsafe {
        libc::close(credential_write);
        // The child must inherit these descriptors. They are deliberately not
        // close-on-exec, and the parent closes its copies after the spawn.
        libc::fcntl(credential_read, libc::F_SETFD, 0);
    }
    let (token_read, token_write) = pipe();
    write_all_fd(token_write, format!("{SECRET}\n").as_bytes());
    write_all_fd(token_write, format!("{SECRET}\n").as_bytes());
    unsafe {
        libc::close(token_write);
        libc::fcntl(token_read, libc::F_SETFD, 0);
    }

    let directory = std::env::temp_dir().join(format!(
        "hotspotshade-handoff-{}-{}-{}-{}",
        label,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        std::thread::current().name().unwrap_or("unnamed")
    ));
    std::fs::create_dir(&directory).expect("private test directory");
    let port_file = directory.join("port");
    let error_file = directory.join("stderr");
    // The helper always passes one grant path. It does not exist until the
    // person authorizes a start. The imported credentials must still refuse a
    // route-changing start without it.
    let grant_file = directory.join("tunnel-grant");
    let error_handle = std::fs::File::create(&error_file).unwrap();
    let mut command = Command::new(engine);
    command.args([
        "gui",
        "--no-open",
        "--port",
        "0",
        "--port-file",
        port_file.to_str().unwrap(),
        "--token-fd",
        &token_read.to_string(),
        "--credentials-fd",
        &credential_read.to_string(),
    ]);
    if pass_grant_path {
        command.args(["--grant-file", grant_file.to_str().unwrap()]);
    }
    let mut child = command
        .stdout(Stdio::null())
        .stderr(Stdio::from(error_handle))
        .spawn()
        .expect("spawn the engine");
    unsafe {
        libc::close(credential_read);
        libc::close(token_read);
    }

    let deadline = Instant::now() + Duration::from_secs(10);
    let port = loop {
        if let Ok(text) = std::fs::read_to_string(&port_file) {
            if let Ok(port) = text.trim().parse::<u16>() {
                break port;
            }
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let stderr = std::fs::read_to_string(&error_file).unwrap_or_default();
            panic!("the engine did not publish its port: {stderr}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    (child, port, directory, grant_file)
}

/// SIGTERM uses the engine's cleanup path. These engines never start a tunnel,
/// so there is nothing to remove.
fn stop_engine(mut child: Child, directory: &std::path::Path) {
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let started = Instant::now();
    loop {
        if let Ok(Some(_)) = child.try_wait() {
            break;
        }
        if started.elapsed() > Duration::from_secs(10) {
            let _ = child.kill();
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn a_root_engine_imports_the_pairing_and_never_returns_the_token() {
    let (child, port, directory, grant_file) = spawn_engine("handoff", true);
    let body = get_status(port, SECRET);
    assert!(
        body.contains("\"paired\":true"),
        "the imported pairing is visible: {body}"
    );
    assert!(body.contains("\"phone_port\":18080"), "{body}");
    assert!(
        !body.contains(TOKEN),
        "the status answer must not carry the token"
    );

    // A root engine that imported credentials is still a helper engine. It
    // must refuse a route-changing start until the helper writes a fresh
    // grant, even though it already holds the pairing.
    let start_body = r#"{"mode":"phone","options":{}}"#;
    let train = post_request(port, "/api/start", start_body);
    assert!(
        train.contains("Administrator authorization is required"),
        "the imported engine must refuse a start without a grant: {train}"
    );
    assert!(
        !grant_file.exists(),
        "a failed grant check must not create a grant file"
    );

    // A root engine must not export a second handoff.
    let answer = post_request(port, "/api/pairing/handoff", "{}");
    assert!(
        answer.contains("409") || answer.contains("handoff_unsupported"),
        "{answer}"
    );

    stop_engine(child, &directory);
}

#[test]
fn a_credentials_engine_with_no_grant_refuses_phone_and_tun_starts() {
    // No --grant-file option at all. This is the missing-grant refusal, not a
    // grant-directory permission check: the engine returns before it reads any
    // path. The test runs as the test user and needs no root.
    let (child, port, directory, grant_file) = spawn_engine("no-grant", false);
    assert!(!grant_file.exists());
    let status = get_status(port, SECRET);
    assert!(
        status.contains("\"paired\":true"),
        "the imported pairing is visible: {status}"
    );

    for mode in ["phone", "tun"] {
        let body = format!(r#"{{"mode":"{mode}"}}"#);
        let reply = post_request(port, "/api/start", &body);
        assert!(
            reply.contains("Administrator authorization is required"),
            "a {mode} start without a grant must refuse: {reply}"
        );
        assert!(
            !reply.contains(TOKEN),
            "the refusal must not carry the token: {reply}"
        );
    }

    stop_engine(child, &directory);
}

#[test]
fn a_handoff_round_trip_keeps_the_pairing_and_hides_the_token_from_debug() {
    let (writer, reader) = UnixStream::pair().unwrap();
    let (write_fd, read_fd) = (writer.into_raw_fd(), reader.into_raw_fd());
    let identity = Identity::from_bytes([0x24; 32]);
    let credentials = PhoneCredentials {
        host: Ipv4Addr::new(10, 0, 0, 1),
        port: 19000,
        token: TOKEN.into(),
    };
    write_handoff(write_fd, &identity, &credentials).unwrap();
    let (imported, imported_credentials) = read_handoff(read_fd).unwrap();
    unsafe {
        libc::close(write_fd);
        libc::close(read_fd);
    }
    assert_eq!(imported.public(), identity.public());
    assert_eq!(imported_credentials.token, TOKEN);
    assert!(!format!("{imported_credentials:?}").contains(TOKEN));
}
