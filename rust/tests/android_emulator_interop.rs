//! Cross-implementation interop test against the Android source server.
//!
//! The test needs a booted Android emulator, the instrumented
//! `SourceSocksInteropTest`, an `adb forward` from this host, and the
//! `HS_EMULATOR_PORT` environment variable. It is ignored by default.
//! Running it explicitly without a valid nonzero port fails. Set
//! `HS_EMULATOR_IPV6_PORT` to the emulator's nonzero IPv6 echo port to require
//! an IPv6 flow; an absent or zero value means that case was not tested.
//!
//! The PhoneProxy outer sockets and the host echo server stay on host
//! loopback. The test sets no route, creates no tunnel device, and uses no
//! carrier, real phone, or DNS lookup. An emulator loopback does not prove
//! carrier or physical device behavior.
#![cfg(any(unix, windows))]

use hotspotshade::{
    normalization::Audit,
    packet,
    phone::{credentials_rejected, PhoneProxy, Target},
    relay::{Relay, RelayConfig},
};
use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket,
};
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

fn emulator_port() -> u16 {
    let value = std::env::var("HS_EMULATOR_PORT")
        .expect("set HS_EMULATOR_PORT to the emulator source-server forward port");
    let port: u16 = value.parse().expect("HS_EMULATOR_PORT must be a TCP port");
    assert_ne!(port, 0, "HS_EMULATOR_PORT must be nonzero");
    port
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
    let port = emulator_port();
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

    // One UDP-over-TCP flow carries two datagrams to a loopback echo server.
    // The emulator reaches the host listener through its 10.0.2.2 alias.
    let udp_echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    udp_echo.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    let udp_port = udp_echo.local_addr().unwrap().port();
    let udp_worker = thread::spawn(move || -> io::Result<Vec<SocketAddr>> {
        let mut buf = [0u8; 1472];
        let mut peers = Vec::new();
        for _ in 0..4 {
            let (len, peer) = udp_echo.recv_from(&mut buf)?;
            peers.push(peer);
            udp_echo.send_to(&buf[..len], peer)?;
        }
        Ok(peers)
    });
    let mut udp = proxy
        .open_udp(Target::Ip(EMULATOR_HOST.into()), udp_port, &audit)
        .expect("the Android source server must open a UDP flow");
    udp.stream.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
    for payload in [b"udp-one".as_slice(), b"udp-two".as_slice()] {
        udp.send(payload)
            .expect("the UDP flow must accept a datagram");
        assert_eq!(
            udp.recv().expect("the UDP flow must return a datagram"),
            payload
        );
    }
    drop(udp);

    // Exercise the real relay as well as PhoneUdp. No tunnel is created: raw
    // inner UDP packets are submitted to its public in-memory API.
    let inner_src = Ipv4Addr::new(198, 18, 0, 2);
    let inner_port = 21567;
    let mut relay = Relay::start(RelayConfig {
        phone: Some(Arc::new(phone(port, TOKEN))),
        allow_unpinned: true,
        workers: 1,
        ..RelayConfig::default()
    })
    .expect("the loopback relay must start");
    for payload in [b"relay-one".as_slice(), b"relay-two".as_slice()] {
        let inner = packet::build_udp(
            inner_src,
            EMULATOR_HOST,
            inner_port,
            udp_port,
            payload,
            64,
            0,
        )
        .expect("the inner datagram must be valid");
        relay
            .dispatch(inner)
            .expect("the relay must accept a datagram");
        let reply = relay
            .recv_timeout(TEST_TIMEOUT)
            .expect("the relay must return a datagram");
        let ip = packet::parse_ip(&reply).expect("the reply must be an IP packet");
        let datagram = packet::parse_udp(ip.payload).expect("the reply must be UDP");
        assert_eq!((ip.src, ip.dst), (EMULATOR_HOST.into(), inner_src.into()));
        assert_eq!((datagram.sport, datagram.dport), (udp_port, inner_port));
        assert_eq!(datagram.data, payload);
    }
    // Complete an inner TCP handshake and echo through the same relay and
    // Android proxy. The host echo service remains on loopback.
    let tcp_port = 21568;
    let build_tcp = |seq, ack, flags, payload| {
        packet::build_tcp(&packet::TcpBuild {
            src: inner_src,
            dst: EMULATOR_HOST,
            sport: tcp_port,
            dport: echo.port,
            seq,
            ack,
            flags,
            window: 65535,
            payload,
            options: &[],
            ttl: 64,
            ident: 0,
        })
        .expect("the inner TCP packet must be valid")
    };
    let mut client_next = 1000u32;
    relay
        .dispatch(build_tcp(client_next, 0, packet::SYN, &[]))
        .unwrap();
    let syn_ack = relay
        .recv_timeout(TEST_TIMEOUT)
        .expect("relay TCP handshake");
    let ip = packet::parse_ip(&syn_ack).expect("valid TCP reply IP");
    let tcp = packet::parse_tcp(ip.payload).expect("valid TCP SYN-ACK");
    assert_eq!(
        tcp.flags & (packet::SYN | packet::ACK),
        packet::SYN | packet::ACK
    );
    assert_eq!(tcp.ack, client_next + 1);
    client_next += 1;
    let mut server_next = tcp.seq.wrapping_add(1);
    relay
        .dispatch(build_tcp(client_next, server_next, packet::ACK, &[]))
        .unwrap();
    let tcp_payload = b"relay-tcp-echo";
    relay
        .dispatch(build_tcp(
            client_next,
            server_next,
            packet::ACK | packet::PSH,
            tcp_payload,
        ))
        .unwrap();
    client_next += tcp_payload.len() as u32;
    let deadline = Instant::now() + TEST_TIMEOUT;
    let mut received = Vec::new();
    while received.len() < tcp_payload.len() && Instant::now() < deadline {
        let raw = relay.recv_timeout(Duration::from_millis(250));
        let Ok(raw) = raw else { continue };
        let ip = packet::parse_ip(&raw).expect("valid TCP reply IP");
        let tcp = packet::parse_tcp(ip.payload).expect("valid TCP reply");
        assert_eq!(
            (ip.src, ip.dst, tcp.sport, tcp.dport),
            (EMULATOR_HOST.into(), inner_src.into(), echo.port, tcp_port)
        );
        assert_eq!(tcp.flags & packet::RST, 0, "relay reset the TCP flow");
        if !tcp.data.is_empty() && tcp.seq == server_next {
            received.extend_from_slice(tcp.data);
            server_next = server_next.wrapping_add(tcp.data.len() as u32);
            relay
                .dispatch(build_tcp(client_next, server_next, packet::ACK, &[]))
                .unwrap();
        }
    }
    assert_eq!(received, tcp_payload);
    let stats = relay.stats();
    assert_eq!(stats.tcp_flows, 1);
    assert_eq!(
        (
            stats.udp_datagrams_in,
            stats.udp_datagrams_out,
            stats.ttl_bad
        ),
        (2, 2, 0)
    );
    relay.stop();
    let peers = udp_worker.join().unwrap().expect("UDP echo server failed");
    assert_eq!(peers[0], peers[1], "PhoneUdp must reuse its UDP flow");
    assert_eq!(
        peers[2], peers[3],
        "the relay must reuse its inner UDP flow"
    );
    assert_ne!(
        peers[0], peers[2],
        "distinct flows must use distinct UDP sockets"
    );

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
    // on the emulator loopback and prints its port. A zero or absent port
    // records a skipped case. A supplied listener must actually work.
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
                let mut stream = proxy
                    .open_tcp(Target::Ip(Ipv6Addr::LOCALHOST.into()), ipv6_port, &audit)
                    .expect("the Android source server must connect to the supplied IPv6 listener");
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
        }
        Err(_) => {
            eprintln!("HS_EMULATOR_IPV6_PORT is not set, so the IPv6 destination case is skipped.");
            false
        }
    };

    let (outer_sockets, ttl_bad) = audit.snapshot();
    let expected_sockets = if ipv6_expected { 6 } else { 5 };
    assert_eq!(
        outer_sockets, expected_sockets,
        "check, TCP echo, UDP flow, token, unreachable, and optional IPv6 socket"
    );
    assert_eq!(ttl_bad, 0, "every outer socket must keep TTL 65");
}
