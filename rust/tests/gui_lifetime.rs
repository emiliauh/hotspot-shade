#![cfg(unix)]
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A unique temporary directory for one test. It removes itself on panic.
struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let mut bytes = [0u8; 8];
        assert_eq!(
            unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()) },
            0
        );
        let suffix: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("hs-fp-{}-{}", std::process::id(), suffix));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Stop the engine on every exit path, including a panic.
struct ChildGuard(Option<Child>);
impl ChildGuard {
    fn new(child: Child) -> Self {
        Self(Some(child))
    }
    fn exited(&mut self) -> bool {
        match self.0.as_mut() {
            Some(child) => child.try_wait().unwrap().is_some(),
            None => true,
        }
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let Some(child) = self.0.as_mut() else {
            return;
        };
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        // The engine removes routes and the port file on SIGTERM.
        unsafe {
            libc::kill(child.id() as i32, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if matches!(child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[test]
fn parent_pipe_and_authenticated_routes() {
    let deadline = Instant::now() + Duration::from_secs(15);
    let dir = TempDir::new();
    let path = dir.join("port");
    let mut parent = [0; 2];
    let mut secret = [0; 2];
    assert_eq!(unsafe { libc::pipe(parent.as_mut_ptr()) }, 0);
    assert_eq!(unsafe { libc::pipe(secret.as_mut_ptr()) }, 0);
    let token = "a".repeat(64);
    let bytes = format!("{token}\n");
    assert_eq!(
        unsafe { libc::write(secret[1], bytes.as_ptr().cast(), bytes.len()) },
        bytes.len() as isize
    );
    unsafe {
        libc::close(secret[1]);
    }
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_hotspotshade"));
    cmd.args(["gui", "--demo", "--no-open", "--port", "0", "--port-file"])
        .arg(&path)
        .args([
            "--parent-fd",
            &parent[0].to_string(),
            "--token-fd",
            &secret[0].to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        cmd.pre_exec(move || {
            libc::close(parent[1]);
            Ok(())
        });
    }
    let child = cmd.spawn().unwrap();
    let mut guard = ChildGuard::new(child);
    unsafe {
        libc::close(parent[0]);
        libc::close(secret[0]);
    }
    while !path.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    let port: u16 = std::fs::read_to_string(&path)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let request = |method: &str, host: &str, authorization: &str, origin: &str| {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write!(stream, "{method} /api/status HTTP/1.1\r\nHost: {host}\r\n{authorization}{origin}Connection: close\r\n\r\n").unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    };
    let host = format!("127.0.0.1:{port}");
    let missing = request("GET", &host, "", "");
    assert!(missing.starts_with("HTTP/1.1 401"));
    assert_eq!(
        missing.split("\r\n\r\n").nth(1).unwrap(),
        r#"{"ok":false,"error":"unauthorized"}"#
    );
    assert!(
        request("GET", &host, "Authorization: Bearer wrong\r\n", "").starts_with("HTTP/1.1 401")
    );
    let auth = format!("Authorization: bEaReR {token}\r\n");
    assert!(request("GET", &host, &auth, "").starts_with("HTTP/1.1 200"));
    let head = request("HEAD", &host, "", "");
    assert!(head.starts_with("HTTP/1.1 401") && head.ends_with("\r\n\r\n"));
    assert!(request("OPTIONS", &host, "", "").starts_with("HTTP/1.1 401"));
    assert!(request("GET", "example.com", &auth, "").starts_with("HTTP/1.1 403"));
    assert!(
        request("GET", &host, &auth, "Origin: http://example.com\r\n").starts_with("HTTP/1.1 403")
    );
    // Closing the parent descriptor makes the engine shut down and clean up.
    unsafe {
        libc::close(parent[1]);
    }
    while !guard.exited() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(guard.exited(), "engine did not exit");
    assert!(!path.exists());
}

#[test]
fn token_fd_rejects_invalid_secret() {
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let invalid = format!("{}\n", "A".repeat(64));
    assert_eq!(
        unsafe { libc::write(fds[1], invalid.as_ptr().cast(), invalid.len()) },
        invalid.len() as isize
    );
    unsafe {
        libc::close(fds[1]);
    }
    let status = Command::new(env!("CARGO_BIN_EXE_hotspotshade"))
        .args([
            "gui",
            "--demo",
            "--no-open",
            "--port",
            "0",
            "--token-fd",
            &fds[0].to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    unsafe {
        libc::close(fds[0]);
    }
    assert!(!status.success());
}
