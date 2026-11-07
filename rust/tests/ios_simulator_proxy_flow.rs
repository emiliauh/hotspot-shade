//! Manual interop test: the Rust target client against the real iOS source
//! proxy in the iOS Simulator.
//!
//! The test needs a Debug Simulator build of the app, the test hotspot pair
//! `lo0` / `127.0.0.1`, `debug.mockCellularPath` enabled, a started proxy, and
//! `HS_IOS_SIM=1`. A first pairing needs a person to tap Allow on the
//! simulator. It is ignored in normal runs.
//!
//! The Debug Simulator build replaces the cellular pin with the host path.
//! Every Release build and every device build keeps the cellular pin. The test
//! destination and the host echo server stay on loopback. The test sets no
//! route, creates no interface, and uses no cellular path, real phone, or
//! carrier. The domain test uses `localhost` only. Simulator loopback does
//! not prove carrier, hotspot, or physical device behavior.
#![cfg(target_os = "macos")]

use hotspotshade::{
    normalization::Audit,
    pairing::{pair_at, Identity, PairTimeouts, PAIRING_PORT},
    phone::{credentials_rejected, PhoneProxy, Target},
};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const USERNAME: &str = "hotspotshade";
const ECHO_BYTES: usize = 64 * 1024 + 37;
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A loopback TCP echo server for the source proxy destination.
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

fn simulator_host() -> Ipv4Addr {
    match std::env::var("HS_IOS_SIM_ADDRESS") {
        Ok(value) => value
            .parse()
            .unwrap_or_else(|_| panic!("HS_IOS_SIM_ADDRESS is not an IPv4 address: {value}")),
        Err(_) => Ipv4Addr::LOCALHOST,
    }
}

fn phone(host: Ipv4Addr, port: u16, token: &str) -> PhoneProxy {
    PhoneProxy {
        address: SocketAddr::from((host, port)),
        username: USERNAME.into(),
        token: token.into(),
        iface: None,
        timeout: TEST_TIMEOUT,
    }
}

fn payload() -> Vec<u8> {
    (0..ECHO_BYTES)
        .map(|index| (index.wrapping_mul(31) + 7) as u8)
        .collect()
}

/// A port with no listener. Bind it, read the port, and release it.
fn closed_port() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("a loopback bind");
    listener.local_addr().expect("the loopback address").port()
}

#[test]
#[ignore = "needs the iOS Simulator, its Debug test override, and HS_IOS_SIM=1"]
fn ios_simulator_source_proxy_serves_tcp_and_reports_failure() {
    assert_eq!(
        std::env::var("HS_IOS_SIM").ok().as_deref(),
        Some("1"),
        "set HS_IOS_SIM=1 only after preparing the simulator test environment"
    );
    let host = simulator_host();
    let address = SocketAddr::from((host, PAIRING_PORT));
    // Hold four silent pairing sockets. The listener must still admit the real
    // target check by evicting the oldest socket that sent no complete frame.
    // Each socket has a bounded read so the test cannot hang.
    let mut silent = Vec::new();
    for _ in 0..4 {
        let socket = TcpStream::connect(address).expect("a silent pairing socket");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("a silent socket must keep a read timeout");
        silent.push(socket);
    }
    // Give the listener time to accept all four before the real check.
    thread::sleep(Duration::from_secs(1));

    // The same fixed public test key as the pairing test. It is not a secret.
    let identity = Identity::from_bytes([0x42; 32]);
    let audit = Audit::default();
    let cancel = AtomicBool::new(false);
    let timeouts = PairTimeouts {
        connect: Duration::from_secs(5),
        challenge: Duration::from_secs(10),
        result: Duration::from_secs(120),
    };
    let credentials = pair_at(
        address,
        &identity,
        None,
        &audit,
        &cancel,
        timeouts,
        |code| {
            eprintln!("PAIRING_CODE {code}");
        },
    )
    .expect("pairing with the simulator");
    eprintln!(
        "PAIRED host={} port={} token_len={}",
        credentials.host,
        credentials.port,
        credentials.token.len()
    );
    assert_eq!(credentials.host, host);
    assert!(credentials.port >= 20000 && credentials.port <= 59999);

    // The listener closed at least one silent socket to admit the real check.
    // A read that times out means that socket is still open.
    let mut evicted = 0;
    for socket in &mut silent {
        let _ = socket.set_read_timeout(Some(Duration::from_millis(500)));
        let mut byte = [0u8; 1];
        match socket.read(&mut byte) {
            Ok(0) => evicted += 1,
            // A peer that closes with unread data may reset the connection
            // instead of returning EOF. Both outcomes prove it is closed.
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ) =>
            {
                evicted += 1
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Ok(_) => panic!("a silent pairing socket must not send data"),
            Err(error) => panic!("a silent pairing socket read failed: {error}"),
        }
    }
    assert!(
        evicted >= 1,
        "the listener must evict an idle socket to admit the target check"
    );

    let echo = EchoServer::start().expect("the host echo listener must bind");
    let proxy = phone(host, credentials.port, &credentials.token);

    // (a) The real source proxy accepts the paired user and token.
    proxy
        .check_cancellable(&audit, &AtomicBool::new(false))
        .expect("the iOS source proxy must accept the token");

    // (b) One TCP CONNECT reaches the host echo server through the proxy.
    let mut stream = proxy
        .open_tcp(
            Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            echo.port,
            &audit,
        )
        .expect("the iOS source proxy must connect to the host echo server");
    stream
        .set_read_timeout(Some(TEST_TIMEOUT))
        .expect("the relay must keep a read timeout");
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

    // A domain target is resolved by the source proxy, not the target client.
    let mut domain_stream = proxy
        .open_tcp(Target::Domain("localhost"), echo.port, &audit)
        .expect("the source proxy must connect to the loopback domain");
    domain_stream.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    domain_stream.write_all(b"domain-echo").unwrap();
    let mut domain_reply = [0u8; 11];
    domain_stream.read_exact(&mut domain_reply).unwrap();
    assert_eq!(&domain_reply, b"domain-echo");
    drop(domain_stream);

    // The same real client carries independent datagrams over one UDP flow.
    let udp_echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    udp_echo.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    let udp_port = udp_echo.local_addr().unwrap().port();
    let udp_worker = thread::spawn(move || -> io::Result<()> {
        let mut buffer = [0u8; 1472];
        for _ in 0..2 {
            let (count, peer) = udp_echo.recv_from(&mut buffer)?;
            udp_echo.send_to(&buffer[..count], peer)?;
        }
        Ok(())
    });
    let mut udp = proxy
        .open_udp(
            Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            udp_port,
            &audit,
        )
        .expect("the source proxy must open a UDP flow");
    udp.stream.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    for datagram in [b"udp-one".as_slice(), b"udp-two".as_slice()] {
        udp.send(datagram).unwrap();
        assert_eq!(udp.recv().unwrap(), datagram);
    }
    drop(udp);
    udp_worker
        .join()
        .unwrap()
        .expect("the UDP echo must finish");

    // A wrong token gets the credentials-rejected error.
    let wrong = phone(host, credentials.port, "not-the-simulator-token");
    let error = wrong
        .check_cancellable(&audit, &AtomicBool::new(false))
        .expect_err("the iOS source proxy must reject a wrong token");
    assert!(
        credentials_rejected(&error),
        "a wrong token must map to credentials_rejected, got {error:?}"
    );
    assert!(
        !error.to_string().contains(&credentials.token),
        "the error must not contain the token"
    );

    // A refused destination gets one mapped error and no open hang.
    let started = Instant::now();
    let error = proxy
        .open_tcp(
            Target::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            closed_port(),
            &audit,
        )
        .expect_err("a refused destination must fail");
    let elapsed = started.elapsed();
    assert_eq!(
        error.kind(),
        io::ErrorKind::ConnectionRefused,
        "a closed loopback port must map to a refusal, got {error:?}: {error}"
    );
    assert!(
        !credentials_rejected(&error),
        "a refused destination is not an authentication failure"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "the refused destination wait was not bounded: {elapsed:?}"
    );

    let (outer_sockets, ttl_bad) = audit.snapshot();
    assert_eq!(
        outer_sockets, 7,
        "pairing, one check, TCP, domain TCP, UDP, wrong-token check, and refusal"
    );
    assert_eq!(ttl_bad, 0, "every outer socket must keep TTL 65");
    eprintln!("IOS_SIM_PROXY_OK audit=({outer_sockets}, {ttl_bad})");
}

/// A pairing socket that sends no complete frame must not hold a slot.
#[test]
#[ignore = "needs the iOS Simulator, its Debug test override, and HS_IOS_SIM=1"]
fn ios_simulator_pairing_listener_closes_a_silent_socket() {
    assert_eq!(
        std::env::var("HS_IOS_SIM").ok().as_deref(),
        Some("1"),
        "set HS_IOS_SIM=1 only after preparing the simulator test environment"
    );
    let host = simulator_host();
    let address = SocketAddr::from((host, PAIRING_PORT));
    let mut idle = TcpStream::connect(address).expect("a silent pairing socket");
    idle.set_read_timeout(Some(Duration::from_secs(25)))
        .expect("the silent socket must keep a read timeout");
    let started = Instant::now();
    let mut byte = [0u8; 1];
    match idle.read(&mut byte) {
        Ok(0) => {}
        Ok(_) => panic!("a silent pairing socket must not receive data"),
        Err(error) => panic!("the silent pairing socket read failed: {error}"),
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_secs(9),
        "the first-frame bound must not close a socket early: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(25),
        "the first-frame bound did not close the socket: {elapsed:?}"
    );
    eprintln!("IOS_SIM_SILENT_CLOSED after={elapsed:?}");
}
