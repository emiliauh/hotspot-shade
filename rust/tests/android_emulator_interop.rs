//! Cross-implementation interop test against the Android source server.
//!
//! The test needs a booted Android emulator, the instrumented
//! `SourceSocksInteropTest`, an `adb forward` from this host, and the
//! `HS_EMULATOR_PORT` environment variable. It is ignored by default.
//!
//! The PhoneProxy outer sockets and the host echo server stay on host
//! loopback. The test sets no route, creates no tunnel device, and uses no
//! carrier, real phone, or DNS lookup. An emulator loopback does not prove
//! carrier or physical device behavior.
#![cfg(any(unix, windows))]

use hotspotshade::{
    normalization::Audit,
    phone::{credentials_rejected, PhoneProxy, Target},
};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const USERNAME: &str = "hotspotshade";
const TOKEN: &str = "emulator-test-token";
const WRONG_TOKEN: &str = "not-the-emulator-token";
const ECHO_BYTES: usize = 64 * 1024 + 37;
const TEST_TIMEOUT: Duration = Duration::from_secs(30);
/// The emulator alias for this host.
const EMULATOR_HOST: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);

/// A loopback TCP echo server for the emulator destination 10.0.2.2.
struct EchoServer {
    port: u16,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl EchoServer {
    fn start() -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            while !worker_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        thread::spawn(move || echo(stream));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            port,
            stop,
            worker: Some(worker),
        })
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn echo(mut stream: TcpStream) {
    // macOS can inherit the nonblocking flag from the listener.
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(TEST_TIMEOUT));
    let mut buffer = [0u8; 16 * 1024];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                if stream.write_all(&buffer[..count]).is_err() {
                    break;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

fn phone(port: u16, token: &str) -> PhoneProxy {
    PhoneProxy {
        address: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        username: USERNAME.into(),
        token: token.into(),
        iface: None,
        timeout: TEST_TIMEOUT,
    }
}

fn emulator_port() -> Option<u16> {
    let value = std::env::var("HS_EMULATOR_PORT").ok()?;
    match value.parse() {
        Ok(port) => Some(port),
        Err(_) => panic!("HS_EMULATOR_PORT is not a TCP port: {value}"),
    }
}

fn payload() -> Vec<u8> {
    (0..ECHO_BYTES)
        .map(|index| (index.wrapping_mul(31) + 7) as u8)
        .collect()
}

/// Send one private echo command (0x81) and return the echoed payload.
///
/// The target device engine does not expose the echo command in `phone.rs`,
/// so the test speaks the authenticated command itself. The socket stays on
/// host loopback and is not part of the normalized outer socket audit.
fn echo_through_android(port: u16, target: IpAddr, payload: &[u8]) -> io::Result<Vec<u8>> {
    let invalid = |message: &'static str| io::Error::new(io::ErrorKind::InvalidData, message);
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))?;
    stream.set_read_timeout(Some(TEST_TIMEOUT))?;
    stream.set_write_timeout(Some(TEST_TIMEOUT))?;
    stream.write_all(&[5, 1, 2])?;
    let mut answer = [0u8; 2];
    stream.read_exact(&mut answer)?;
    if answer != [5, 2] {
        return Err(invalid("the echo session greeting was rejected"));
    }
    let mut auth = vec![1, USERNAME.len() as u8];
    auth.extend_from_slice(USERNAME.as_bytes());
    auth.push(TOKEN.len() as u8);
    auth.extend_from_slice(TOKEN.as_bytes());
    stream.write_all(&auth)?;
    stream.read_exact(&mut answer)?;
    if answer != [1, 0] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the echo session token was rejected",
        ));
    }
    let address_type = match target {
        IpAddr::V4(_) => 1,
        IpAddr::V6(_) => 4,
    };
    let mut request = vec![5, 0x81, 0, address_type];
    match target {
        IpAddr::V4(ip) => request.extend_from_slice(&ip.octets()),
        IpAddr::V6(ip) => request.extend_from_slice(&ip.octets()),
    }
    request.extend_from_slice(&0u16.to_be_bytes());
    stream.write_all(&request)?;
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply)?;
    if reply[0] != 5 || reply[1] != 0 {
        return Err(invalid("the echo command was refused"));
    }
    stream.write_all(&(payload.len() as u16).to_be_bytes())?;
    stream.write_all(payload)?;
    let mut header = [0u8; 3];
    stream.read_exact(&mut header)?;
    let status = header[0];
    let length = u16::from_be_bytes([header[1], header[2]]) as usize;
    if status != 0 {
        return Err(invalid("the source device did not complete the echo"));
    }
    if length > 1200 || length != payload.len() {
        return Err(invalid("the echo reply has the wrong length"));
    }
    let mut echoed = vec![0u8; length];
    stream.read_exact(&mut echoed)?;
    Ok(echoed)
}

#[test]
#[ignore = "needs a booted Android emulator and HS_EMULATOR_PORT"]
fn android_source_server_interop() {
    let Some(port) = emulator_port() else {
        eprintln!("HS_EMULATOR_PORT is not set, so the Android interop test is skipped.");
        return;
    };
    let echo = EchoServer::start().expect("the host echo listener must bind");
    let audit = Audit::default();
    let proxy = phone(port, TOKEN);

    // (a) The Android server accepts the pinned user and token.
    proxy
        .check_cancellable(&audit, &AtomicBool::new(false))
        .expect("the Android source server must accept the token");

    // (b) One TCP CONNECT reaches this Mac through the emulator alias 10.0.2.2.
    let mut stream = proxy
        .open_tcp(
            Target::Ip(Ipv4Addr::new(10, 0, 2, 2).into()),
            echo.port,
            &audit,
        )
        .expect("the Android source server must connect to the host echo server");
    let sent = payload();
    assert!(
        sent.len() >= 64 * 1024,
        "the payload must be at least 64 KiB"
    );
    stream
        .write_all(&sent)
        .expect("the relay must accept the full payload");
    let mut received = vec![0u8; sent.len()];
    stream
        .read_exact(&mut received)
        .expect("the relay must echo the full payload");
    assert_eq!(received, sent, "the echo must return every byte unchanged");
    let _ = stream.shutdown(Shutdown::Both);
    drop(stream);

    // (c) A wrong token gets the credentials-rejected error.
    let wrong = phone(port, WRONG_TOKEN);
    let error = wrong
        .check_cancellable(&audit, &AtomicBool::new(false))
        .expect_err("the Android source server must reject a wrong token");
    assert!(
        credentials_rejected(&error),
        "a wrong token must map to credentials_rejected, got {error:?}"
    );
    assert!(
        !error.to_string().contains(TOKEN),
        "the error must not contain the token"
    );

    // (d) An unreachable destination gets one mapped error and no open hang.
    let started = Instant::now();
    let error = proxy
        .open_tcp(Target::Ip(Ipv4Addr::BROADCAST.into()), 9, &audit)
        .expect_err("an unreachable destination must fail");
    let elapsed = started.elapsed();
    assert!(
        matches!(
            error.kind(),
            io::ErrorKind::NetworkUnreachable
                | io::ErrorKind::HostUnreachable
                | io::ErrorKind::ConnectionRefused
                | io::ErrorKind::Other
        ),
        "the source device reply must map to an error, got {:?}: {error}",
        error.kind()
    );
    assert!(
        !credentials_rejected(&error),
        "an unreachable destination is not an authentication failure"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "the unreachable destination wait was not bounded: {elapsed:?}"
    );

    // (e) One ICMP echo request goes through the private echo command. The
    // emulator reaches this host at 10.0.2.2.
    let echo_payload = b"hs-android-echo";
    let echoed = echo_through_android(port, EMULATOR_HOST.into(), echo_payload)
        .expect("the Android source server must relay an ICMP echo");
    assert_eq!(
        echoed, echo_payload,
        "the echo must return the payload unchanged"
    );

    // (f) One IPv6 destination. The instrumented test serves an echo listener
    // on the emulator loopback and prints its port. An emulator without an
    // IPv6 path reports port 0 or a network or host unreachable error, so the
    // case is skipped with a message. It is never faked.
    let ipv6_expected = match std::env::var("HS_EMULATOR_IPV6_PORT") {
        Ok(value) => {
            let ipv6_port: u16 = value
                .parse()
                .unwrap_or_else(|_| panic!("HS_EMULATOR_IPV6_PORT is not a TCP port: {value}"));
            if ipv6_port == 0 {
                eprintln!(
                    "The emulator reported no IPv6 loopback listener, so the IPv6 destination case is skipped."
                );
                false
            } else {
                match proxy.open_tcp(Target::Ip(Ipv6Addr::LOCALHOST.into()), ipv6_port, &audit) {
                    Ok(mut stream) => {
                        stream
                            .set_read_timeout(Some(TEST_TIMEOUT))
                            .expect("the IPv6 flow must keep a read timeout");
                        stream
                            .write_all(b"v6-echo")
                            .expect("the IPv6 flow must accept data");
                        let mut reply = [0u8; 7];
                        stream
                            .read_exact(&mut reply)
                            .expect("the IPv6 flow must return the echo");
                        assert_eq!(&reply, b"v6-echo", "the IPv6 echo must return every byte");
                        true
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable
                        ) =>
                    {
                        eprintln!(
                            "The emulator has no IPv6 route, so the IPv6 destination case is skipped: {error}"
                        );
                        true
                    }
                    Err(error) => {
                        panic!("the Android source server must connect to the emulator IPv6 echo: {error}")
                    }
                }
            }
        }
        Err(_) => {
            eprintln!("HS_EMULATOR_IPV6_PORT is not set, so the IPv6 destination case is skipped.");
            false
        }
    };

    let (outer_sockets, ttl_bad) = audit.snapshot();
    let expected_sockets = if ipv6_expected { 5 } else { 4 };
    assert_eq!(
        outer_sockets, expected_sockets,
        "check, echo, token, unreachable, and the optional IPv6 socket"
    );
    assert_eq!(ttl_bad, 0, "every outer socket must keep TTL 65");
}
