//! A real TLS handshake through the ClientHello record shaper.
//!
//! The test starts a loopback TLS 1.3 server with the host `openssl` binary,
//! starts the loopback SOCKS server with shaping explicitly enabled, and puts
//! a dumb byte pipe in front of the SOCKS server. A host `openssl s_client`
//! completes one TLS 1.3 handshake and one HTTP request through the shaped
//! relay.
//!
//! A tap between the shaped relay and the TLS server records the bytes that
//! the shaper actually wrote. The test parses those bytes and asserts that the
//! first ClientHello arrived as many small handshake records whose payload
//! reassembles to the exact ClientHello message that `s_client` sent. A tap in
//! front of the SOCKS server records the unshaped stream, so the test can also
//! assert that the client sent the ClientHello in one larger record. The two
//! recordings together prove that the shaper ran and changed only the record
//! framing.
//!
//! The test is hermetic. Every socket is loopback. It creates no route, no
//! interface, no TUN device, and no child process other than `openssl` on
//! loopback. It needs no root, no source device, and no external endpoint.
//!
//! It does not prove a carrier, a hotspot, a physical phone, SNI hiding, or
//! TCP segmentation. It does not test the iOS or Android relay ports.
//!
//! When no `openssl` binary is found, the test prints a note and returns on a
//! developer machine. Under CI it fails, so a runner without `openssl` cannot
//! silently skip it. Set `HOTSPOTSHADE_OPENSSL` to choose a binary.
#![cfg(unix)]

use hotspotshade::dns::TinyResolver;
use hotspotshade::normalization::Audit;
use hotspotshade::socks::SocksServer;
use hotspotshade::tls_shape::{ShapeLimits, MAX_TLS_RECORD_PAYLOAD};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// The most bytes each tap records. A ClientHello is far smaller.
const RECORD_LIMIT: usize = 8192;
/// The most leading small records the shaping assertion reads.
const SMALL_RECORD_LIMIT: usize = 512;

/// A temporary directory that removes itself.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> io::Result<Self> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "hotspotshade-shape-{}-{}",
            std::process::id(),
            nanos
        ));
        std::fs::create_dir_all(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A child process that is killed and reaped when it is dropped.
struct ChildGuard(Option<Child>);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn openssl() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("HOTSPOTSHADE_OPENSSL") {
        return Some(PathBuf::from(path));
    }
    for candidate in [
        "/usr/bin/openssl",
        "/usr/local/bin/openssl",
        "/opt/homebrew/bin/openssl",
    ] {
        if Path::new(candidate).is_file() {
            return Some(PathBuf::from(candidate));
        }
    }
    None
}

fn free_port() -> io::Result<u16> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    Ok(listener.local_addr()?.port())
}

/// Create a throwaway certificate for the loopback TLS server. The key lives
/// in a temporary directory and is never committed.
fn make_certificate(openssl: &Path, dir: &Path) -> io::Result<(PathBuf, PathBuf)> {
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    let status = Command::new(openssl)
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-keyout",
            key.to_str().unwrap(),
            "-out",
            cert.to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()?;
    if !status.status.success() {
        return Err(io::Error::other(format!(
            "openssl req failed: {}",
            String::from_utf8_lossy(&status.stderr)
        )));
    }
    Ok((cert, key))
}

/// Run one command with a bound and collect its output.
fn run_with_deadline(
    mut command: Command,
    stdin: &[u8],
    limit: Duration,
) -> io::Result<(bool, Vec<u8>, Vec<u8>)> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut input) = child.stdin.take() {
        input.write_all(stdin)?;
        drop(input);
    }
    let started = Instant::now();
    loop {
        match child.try_wait()? {
            Some(_) => break,
            None if started.elapsed() > limit => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the TLS client did not finish",
                ));
            }
            None => thread::sleep(Duration::from_millis(25)),
        }
    }
    let output = child.wait_with_output()?;
    Ok((output.status.success(), output.stdout, output.stderr))
}

/// Copy one stream to another and keep the first bytes for inspection.
fn copy_and_record(mut from: TcpStream, mut to: TcpStream, seen: Arc<Mutex<Vec<u8>>>) {
    let mut buffer = [0u8; 8192];
    loop {
        let read = match from.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue
            }
            Err(_) => break,
        };
        {
            let mut seen = seen.lock().unwrap();
            if seen.len() < RECORD_LIMIT {
                let take = (RECORD_LIMIT - seen.len()).min(read);
                seen.extend_from_slice(&buffer[..take]);
            }
        }
        if to.write_all(&buffer[..read]).is_err() {
            break;
        }
    }
    let _ = to.shutdown(Shutdown::Write);
}

/// Read the first TLS record length and content type from a stream.
fn first_record(bytes: &[u8]) -> Option<(u8, usize)> {
    if bytes.len() < 5 {
        return None;
    }
    Some((
        bytes[0],
        usize::from(u16::from_be_bytes([bytes[3], bytes[4]])),
    ))
}

/// Reassemble the first handshake message from a TLS record stream. The
/// ClientHello can span records, so read records until its declared length is
/// covered. Return the message and the payload length of the first record.
fn first_handshake_message(bytes: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut offset = 0;
    let mut payload = Vec::new();
    let mut first_len = None;
    while offset + 5 <= bytes.len() {
        if bytes[offset] != 22 || bytes[offset + 1] != 3 {
            return None;
        }
        let len = usize::from(u16::from_be_bytes([bytes[offset + 3], bytes[offset + 4]]));
        if len > MAX_TLS_RECORD_PAYLOAD || offset + 5 + len > bytes.len() {
            return None;
        }
        first_len.get_or_insert(len);
        payload.extend_from_slice(&bytes[offset + 5..offset + 5 + len]);
        offset += 5 + len;
        if payload.len() >= 4 && payload[0] == 1 {
            let declared = (usize::from(payload[1]) << 16)
                | (usize::from(payload[2]) << 8)
                | usize::from(payload[3]);
            let total = declared + 4;
            if payload.len() >= total {
                payload.truncate(total);
                return Some((payload, first_len.unwrap_or(0)));
            }
        }
    }
    None
}

/// Collect the leading handshake records whose payload is at most 8 bytes.
/// Stop at the first record that is not one. Return the payload bytes and the
/// record count.
fn shaped_prefix(bytes: &[u8]) -> (Vec<u8>, usize) {
    let mut offset = 0;
    let mut payload = Vec::new();
    let mut count = 0;
    while count < SMALL_RECORD_LIMIT && offset + 5 <= bytes.len() {
        if bytes[offset] != 22 || bytes[offset + 1] != 3 {
            break;
        }
        let len = usize::from(u16::from_be_bytes([bytes[offset + 3], bytes[offset + 4]]));
        if len == 0 || len > 8 || offset + 5 + len > bytes.len() {
            break;
        }
        payload.extend_from_slice(&bytes[offset + 5..offset + 5 + len]);
        offset += 5 + len;
        count += 1;
    }
    (payload, count)
}

/// A loopback byte pipe. It opens one SOCKS5 CONNECT to the shaped SOCKS
/// server and then copies bytes both ways. It adds no framing and changes no
/// byte. It records the bytes the client sends, before the shaper sees them.
struct SocksPipe {
    port: u16,
    seen: Arc<Mutex<Vec<u8>>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl SocksPipe {
    fn start(socks: SocketAddr, target: SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = listener.local_addr()?.port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let worker = thread::spawn(move || {
            let Ok((client, _)) = listener.accept() else {
                return;
            };
            let _ = pipe_one(client, socks, target, recorder);
        });
        Ok(Self {
            port,
            seen,
            worker: Some(worker),
        })
    }

    fn unshaped(&self) -> Vec<u8> {
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for SocksPipe {
    fn drop(&mut self) {
        // The worker ends when the client closes, or when the test binary
        // exits. Do not join here: a client that failed before it connected
        // would leave the worker blocked in accept.
        let _ = self.worker.take();
    }
}

fn pipe_one(
    client: TcpStream,
    socks: SocketAddr,
    target: SocketAddr,
    seen: Arc<Mutex<Vec<u8>>>,
) -> io::Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(20)))?;
    let mut outer = TcpStream::connect(socks)?;
    outer.set_read_timeout(Some(Duration::from_secs(20)))?;
    outer.write_all(&[5, 1, 0])?;
    let mut method = [0u8; 2];
    outer.read_exact(&mut method)?;
    if method != [5, 0] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the SOCKS server refused method 0",
        ));
    }
    let IpAddr::V4(ip) = target.ip() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the pipe needs an IPv4 target",
        ));
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&ip.octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    outer.write_all(&request)?;
    let mut reply = [0u8; 10];
    outer.read_exact(&mut reply)?;
    if reply[0] != 5 || reply[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("the SOCKS request failed with code {}", reply[1]),
        ));
    }
    let mut reader = outer.try_clone()?;
    let mut writer = client.try_clone()?;
    let back = thread::spawn(move || {
        let _ = io::copy(&mut reader, &mut writer);
        let _ = writer.shutdown(Shutdown::Write);
    });
    copy_and_record(client, outer, seen);
    let _ = back.join();
    Ok(())
}

/// A loopback tap in front of the TLS server. The shaped relay connects here,
/// so the recorded bytes are exactly what the shaper wrote. The tap forwards
/// both directions unchanged to the real server.
struct DestinationTap {
    port: u16,
    seen: Arc<Mutex<Vec<u8>>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl DestinationTap {
    fn start(target: SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = listener.local_addr()?.port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let worker = thread::spawn(move || {
            let Ok((client, _)) = listener.accept() else {
                return;
            };
            let _ = tap_one(client, target, recorder);
        });
        Ok(Self {
            port,
            seen,
            worker: Some(worker),
        })
    }

    fn shaped(&self) -> Vec<u8> {
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for DestinationTap {
    fn drop(&mut self) {
        let _ = self.worker.take();
    }
}

fn tap_one(client: TcpStream, target: SocketAddr, seen: Arc<Mutex<Vec<u8>>>) -> io::Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(20)))?;
    let outer = TcpStream::connect(target)?;
    outer.set_read_timeout(Some(Duration::from_secs(20)))?;
    let mut reader = outer.try_clone()?;
    let mut writer = client.try_clone()?;
    let back = thread::spawn(move || {
        let _ = io::copy(&mut reader, &mut writer);
        let _ = writer.shutdown(Shutdown::Write);
    });
    copy_and_record(client, outer, seen);
    let _ = back.join();
    Ok(())
}

#[test]
fn a_real_tls13_handshake_survives_client_hello_reframing() {
    let Some(openssl) = openssl() else {
        assert!(
            std::env::var_os("CI").is_none(),
            "the loopback handshake test needs an openssl binary under CI; \
             set HOTSPOTSHADE_OPENSSL or install openssl"
        );
        eprintln!("SKIP: no openssl binary; the record identity tests still run");
        return;
    };
    // A non-executable or missing override is an error, not a skip.
    let version = Command::new(&openssl)
        .arg("version")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap_or_else(|error| panic!("cannot run {}: {error}", openssl.display()));
    assert!(
        version.status.success(),
        "{} version failed: {}",
        openssl.display(),
        String::from_utf8_lossy(&version.stderr)
    );
    let dir = TempDir::new().expect("a temporary directory");
    let (cert, key) = make_certificate(&openssl, dir.path()).expect("a loopback certificate");
    let server_port = free_port().expect("a free TLS server port");

    let server_error_path = dir.path().join("server.err");
    let server_error = std::fs::File::create(&server_error_path).expect("a server error file");
    let server = Command::new(&openssl)
        .args([
            "s_server",
            "-4",
            "-accept",
            &server_port.to_string(),
            "-cert",
            cert.to_str().unwrap(),
            "-key",
            key.to_str().unwrap(),
            "-tls1_3",
            "-www",
            "-state",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(server_error))
        .spawn()
        .expect("the loopback TLS server starts");
    let server = ChildGuard(Some(server));
    // Give the listener time to bind. It accepts only one connection, so a
    // probe connection would consume that accept.
    thread::sleep(Duration::from_millis(500));

    let audit = Arc::new(Audit::default());
    let resolver = Arc::new(
        TinyResolver::new(
            vec!["127.0.0.1:9".parse().unwrap()],
            None,
            Duration::from_secs(1),
        )
        .unwrap(),
    );
    let mut socks = SocksServer::start_with_shape(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        resolver,
        None,
        Arc::clone(&audit),
        Some(ShapeLimits::default()),
    )
    .expect("the shaped SOCKS server starts");
    let server_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port);
    // The tap sits after the shaper and before the TLS server, so what it
    // records is the byte stream the shaper wrote.
    let tap = DestinationTap::start(server_address).expect("the destination tap starts");
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), tap.port);
    let pipe = SocksPipe::start(socks.address, target).expect("the loopback pipe starts");

    let mut command = Command::new(&openssl);
    command.args([
        "s_client",
        "-connect",
        &format!("127.0.0.1:{}", pipe.port),
        "-tls1_3",
        "-quiet",
    ]);
    let (success, stdout, stderr) =
        run_with_deadline(command, b"GET / HTTP/1.0\r\n\r\n", Duration::from_secs(30))
            .expect("the TLS client finishes");
    let stdout = String::from_utf8_lossy(&stdout);
    let stderr = String::from_utf8_lossy(&stderr);
    let server_log = std::fs::read_to_string(&server_error_path).unwrap_or_default();
    assert!(
        stdout.contains("HTTP/1.0 200 ok"),
        "the shaped relay carried a real TLS handshake and HTTP response; \
         stdout: {stdout:?} stderr: {stderr:?} server: {server_log:?}"
    );
    assert!(
        success,
        "the TLS client reports success; stderr: {stderr:?}"
    );

    // The client sent the ClientHello in one record. This is what makes the
    // small records in the tap proof that the shaper ran.
    let unshaped = pipe.unshaped();
    let (message, client_record_len) = first_handshake_message(&unshaped)
        .expect("the pipe recorded one complete ClientHello from the client");
    assert!(
        client_record_len > 8,
        "the client sent the ClientHello in one record of {client_record_len} bytes, \
         so the small records come from the shaper"
    );
    assert_eq!(
        first_record(&unshaped),
        Some((22, client_record_len)),
        "the unshaped stream starts with one handshake record"
    );

    // The shaper wrote the ClientHello as many records of 1 to 8 payload
    // bytes, and those payloads reassemble to exactly the same message.
    let shaped = tap.shaped();
    let (shaped_bytes, small_records) = shaped_prefix(&shaped);
    assert!(
        small_records >= 8,
        "the shaper wrote {small_records} small records; expected at least 8. \
         First bytes: {:?}",
        &shaped[..shaped.len().min(32)]
    );
    assert_eq!(
        shaped_bytes, message,
        "the shaped records carry the same ClientHello bytes as the client sent"
    );

    socks.stop();
    let (flows, bad) = audit.snapshot();
    assert!(flows >= 1, "the relay opened one audited outer socket");
    assert_eq!(bad, 0, "the TTL audit stays clean");
    drop(server);
    drop(pipe);
    drop(tap);
}
