//! Hermetic loopback tests for the public source device proxy client.
//!
//! The client and mock run on Unix and Windows. These tests do not exercise
//! the Unix-only local adapter or a Windows tunnel.
//!
//! No test here needs root, a route, a TUN device, a real source device, or a
//! DNS lookup.
#![cfg(any(unix, windows))]

mod support;

use hotspotshade::{
    normalization::Audit,
    phone::{authentication_rejected, credentials_rejected, PhoneProxy, Target},
};
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use support::socks::{
    MockSocksSource, SocksAddress, SocksConfig, SocksEvent, SocksFault, SocksPayload,
};
use support::{DOC_IPV4, DOC_IPV6, TEST_DOMAIN, TEST_TOKEN, TEST_USER};

fn proxy(address: SocketAddr, timeout: Duration) -> PhoneProxy {
    PhoneProxy {
        address,
        username: TEST_USER.into(),
        token: TEST_TOKEN.into(),
        iface: None,
        timeout,
    }
}

#[test]
fn ipv6_target_is_carried_in_the_request_and_not_dialed() {
    let mut mock = MockSocksSource::start(SocksConfig::default()).unwrap();
    let audit = Audit::default();
    let phone = proxy(mock.address(), Duration::from_secs(2));
    let mut stream = phone
        .open_tcp(Target::Ip(DOC_IPV6.into()), 443, &audit)
        .unwrap();
    stream.write_all(b"v6").unwrap();
    let mut echo = [0u8; 2];
    stream.read_exact(&mut echo).unwrap();
    assert_eq!(&echo, b"v6");
    drop(stream);

    assert_eq!(audit.snapshot(), (1, 0));
    let report = mock.stop();
    report.assert_clean();
    let request = report.observations[0]
        .request
        .as_ref()
        .expect("IPv6 CONNECT request");
    assert_eq!(request.address, SocksAddress::V6(DOC_IPV6.octets()));
    assert_eq!(request.port, 443);
}

#[test]
fn a_source_refusal_is_not_reported_as_a_connected_flow() {
    let mut mock = MockSocksSource::start(SocksConfig {
        reply: 5,
        ..Default::default()
    })
    .unwrap();
    let audit = Audit::default();
    let error = proxy(mock.address(), Duration::from_secs(2))
        .open_tcp(Target::Domain(TEST_DOMAIN), 443, &audit)
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
    assert_eq!(audit.snapshot(), (1, 0));
    let report = mock.stop();
    report.assert_clean();
    assert!(report.observations[0].request.is_some());
}

#[test]
fn authenticated_tcp_connect_forwards_the_domain_without_local_dns() {
    let mut mock = MockSocksSource::start(SocksConfig::default()).unwrap();
    let audit = Audit::default();
    let phone = proxy(mock.address(), Duration::from_secs(2));

    phone.check(&audit).unwrap();
    let mut stream = phone
        .open_tcp(Target::Domain(TEST_DOMAIN), 443, &audit)
        .unwrap();
    stream.write_all(b"request").unwrap();
    let mut echo = [0u8; 7];
    stream.read_exact(&mut echo).unwrap();
    assert_eq!(&echo, b"request");
    drop(stream);

    assert_eq!(audit.snapshot(), (2, 0), "both outer sockets are audited");
    let report = mock.stop();
    report.assert_clean();
    assert_eq!(report.connections, 2);
    assert!(report.observations.iter().all(|item| item.greeting_ok));
    assert!(report.observations.iter().all(|item| item.auth_ok));

    let checked = report
        .observations
        .iter()
        .find(|item| item.connection == 0)
        .expect("check observation");
    assert!(checked.request.is_none(), "check sends no target");
    assert_eq!(checked.auth_token_len, TEST_TOKEN.len());

    let connected = report
        .observations
        .iter()
        .find(|item| item.connection == 1)
        .expect("connect observation");
    let request = connected.request.as_ref().expect("CONNECT request");
    assert_eq!(request.command, 1);
    assert_eq!(request.port, 443);
    assert_eq!(
        request.address,
        SocksAddress::Domain(TEST_DOMAIN.into()),
        "the source device receives the name unchanged"
    );
    assert!(connected.peer_closed_after_reply);
}

#[test]
fn each_inner_flow_gets_one_outer_socket() {
    let mut mock = MockSocksSource::start(SocksConfig::default()).unwrap();
    let audit = Audit::default();
    let phone = proxy(mock.address(), Duration::from_secs(2));

    let mut first = phone
        .open_tcp(Target::Domain("one.example.test"), 443, &audit)
        .unwrap();
    let mut second = phone
        .open_tcp(Target::Ip(DOC_IPV4.into()), 80, &audit)
        .unwrap();
    first.write_all(b"a").unwrap();
    second.write_all(b"bb").unwrap();
    let mut one = [0u8; 1];
    first.read_exact(&mut one).unwrap();
    let mut two = [0u8; 2];
    second.read_exact(&mut two).unwrap();
    assert_eq!(&one, b"a");
    assert_eq!(&two, b"bb");
    drop(first);
    drop(second);

    assert_eq!(audit.snapshot(), (2, 0));
    let report = mock.stop();
    report.assert_clean();
    assert_eq!(report.connections, 2);
    let addresses: Vec<SocksAddress> = report
        .observations
        .iter()
        .filter_map(|item| item.request.as_ref())
        .map(|request| request.address.clone())
        .collect();
    assert!(addresses.contains(&SocksAddress::Domain("one.example.test".into())));
    assert!(addresses.contains(&SocksAddress::V4(DOC_IPV4.octets())));
}

#[test]
fn fragmented_source_replies_are_reassembled() {
    let mut mock = MockSocksSource::start(SocksConfig {
        fault: SocksFault::FragmentedReplies,
        ..Default::default()
    })
    .unwrap();
    let audit = Audit::default();
    let phone = proxy(mock.address(), Duration::from_secs(2));
    let mut stream = phone
        .open_tcp(Target::Domain(TEST_DOMAIN), 443, &audit)
        .unwrap();
    stream.write_all(b"fragment").unwrap();
    let mut echo = [0u8; 8];
    stream.read_exact(&mut echo).unwrap();
    assert_eq!(&echo, b"fragment");
    drop(stream);

    assert_eq!(audit.snapshot(), (1, 0));
    let report = mock.stop();
    report.assert_clean();
    assert!(report.observations[0].auth_ok);
    assert!(report.observations[0].request.is_some());
}

#[test]
fn authentication_rejections_have_distinct_errors_and_no_token_echo() {
    let audit = Audit::default();

    let mut method = MockSocksSource::start(SocksConfig {
        fault: SocksFault::RejectMethod,
        ..Default::default()
    })
    .unwrap();
    let error = proxy(method.address(), Duration::from_secs(2))
        .check(&audit)
        .unwrap_err();
    assert!(authentication_rejected(&error));
    assert!(!credentials_rejected(&error));
    assert!(!error.to_string().contains(TEST_TOKEN));
    method.stop().assert_clean();

    let mut token = MockSocksSource::start(SocksConfig {
        fault: SocksFault::RejectCredentials,
        ..Default::default()
    })
    .unwrap();
    let error = proxy(token.address(), Duration::from_secs(2))
        .check(&audit)
        .unwrap_err();
    assert!(authentication_rejected(&error));
    assert!(credentials_rejected(&error));
    assert!(!error.to_string().contains(TEST_TOKEN));
    token.stop().assert_clean();

    assert_eq!(audit.snapshot(), (2, 0));
}

#[test]
fn bounded_source_faults_never_report_success() {
    enum Call {
        Check,
        OpenTcp,
    }
    let cases: &[(SocksFault, Call, &str)] = &[
        (SocksFault::SilentAfterGreeting, Call::Check, "silent"),
        (
            SocksFault::CloseBeforeMethodReply,
            Call::Check,
            "close before method",
        ),
        (
            SocksFault::PartialMethodReply,
            Call::Check,
            "partial method",
        ),
        (
            SocksFault::CloseBeforeAuthReply,
            Call::Check,
            "close before auth",
        ),
        (SocksFault::PartialAuthReply, Call::Check, "partial auth"),
        (
            SocksFault::CloseBeforeConnectReply,
            Call::OpenTcp,
            "close before connect",
        ),
        (
            SocksFault::PartialConnectReply,
            Call::OpenTcp,
            "partial connect",
        ),
    ];
    let audit = Audit::default();

    for (fault, call, label) in cases {
        let mut mock = MockSocksSource::start(SocksConfig {
            fault: *fault,
            ..Default::default()
        })
        .unwrap();
        let phone = proxy(mock.address(), Duration::from_millis(300));
        let started = Instant::now();
        let result = match *call {
            Call::Check => phone.check(&audit),
            Call::OpenTcp => phone
                .open_tcp(Target::Domain(TEST_DOMAIN), 443, &audit)
                .map(|_| ()),
        };
        let error = result.expect_err(label);
        match fault {
            SocksFault::SilentAfterGreeting => assert!(
                matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ),
                "{label}: unexpected error kind {:?}",
                error.kind()
            ),
            _ => assert_eq!(
                error.kind(),
                io::ErrorKind::UnexpectedEof,
                "{label}: a short or closed reply is a truncation"
            ),
        }
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{label}: wait was not bounded"
        );
        let report = mock.stop();
        report.assert_clean();
        assert_eq!(report.connections, 1, "{label}");
    }

    assert_eq!(audit.snapshot(), (cases.len() as u64, 0));
}

#[test]
fn cancellation_interrupts_a_silent_source_and_closes_the_outer_socket() {
    let mut mock = MockSocksSource::start(SocksConfig {
        fault: SocksFault::SilentAfterGreeting,
        ..Default::default()
    })
    .unwrap();
    let address = mock.address();
    let audit = Arc::new(Audit::default());
    let cancel = Arc::new(AtomicBool::new(false));
    let phone = proxy(address, Duration::from_secs(10));
    let worker_audit = Arc::clone(&audit);
    let worker_cancel = Arc::clone(&cancel);
    let worker = thread::spawn(move || phone.check_cancellable(&worker_audit, &worker_cancel));

    assert!(
        mock.wait_for(SocksEvent::Greeting, Duration::from_secs(2)),
        "the mock did not see the greeting"
    );
    let started = Instant::now();
    cancel.store(true, Ordering::Release);
    let error = worker.join().unwrap().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "cancellation was not prompt"
    );
    assert_eq!(audit.snapshot(), (1, 0));
    mock.stop().assert_clean();
}

#[test]
fn udp_over_tcp_frames_round_trip_and_reject_oversize() {
    let mut mock = MockSocksSource::start(SocksConfig {
        payload: SocksPayload::UdpEcho { frames: 2 },
        ..Default::default()
    })
    .unwrap();
    let audit = Audit::default();
    let phone = proxy(mock.address(), Duration::from_secs(2));
    let mut udp = phone
        .open_udp(Target::Ip(DOC_IPV4.into()), 53, &audit)
        .unwrap();

    udp.send(b"query").unwrap();
    assert_eq!(udp.recv().unwrap(), b"query");
    udp.send(b"").unwrap();
    assert_eq!(udp.recv().unwrap(), Vec::<u8>::new());
    assert!(udp.send(&vec![0u8; 1473]).is_err());
    drop(udp);

    assert_eq!(audit.snapshot(), (1, 0));
    let report = mock.stop();
    report.assert_clean();
    assert_eq!(report.connections, 1);
    let observation = &report.observations[0];
    let request = observation.request.as_ref().expect("UDP request");
    assert_eq!(request.command, 0x80);
    assert_eq!(request.address, SocksAddress::V4(DOC_IPV4.octets()));
    assert_eq!(request.port, 53);
    assert_eq!(
        observation.udp_in,
        vec![b"query".to_vec(), Vec::new()],
        "the source device receives length-prefixed datagrams"
    );
    assert_eq!(observation.udp_out, observation.udp_in);
}

#[test]
fn udp_frame_errors_are_bounded() {
    let audit = Audit::default();

    let mut oversize = MockSocksSource::start(SocksConfig {
        payload: SocksPayload::UdpOversizeReply,
        ..Default::default()
    })
    .unwrap();
    let mut udp = proxy(oversize.address(), Duration::from_secs(2))
        .open_udp(Target::Ip(DOC_IPV4.into()), 53, &audit)
        .unwrap();
    udp.send(b"x").unwrap();
    let error = udp.recv().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    drop(udp);
    oversize.stop().assert_clean();

    let mut short = MockSocksSource::start(SocksConfig {
        payload: SocksPayload::UdpCloseAfterFirstFrame,
        ..Default::default()
    })
    .unwrap();
    let mut udp = proxy(short.address(), Duration::from_secs(2))
        .open_udp(Target::Ip(DOC_IPV4.into()), 53, &audit)
        .unwrap();
    udp.send(b"x").unwrap();
    let error = udp.recv().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    drop(udp);
    short.stop().assert_clean();

    assert_eq!(audit.snapshot(), (2, 0));
}

#[test]
fn a_silent_udp_source_is_bounded_by_the_client_timeout() {
    let mut mock = MockSocksSource::start(SocksConfig {
        payload: SocksPayload::UdpSilent,
        ..Default::default()
    })
    .unwrap();
    let audit = Audit::default();
    let mut udp = proxy(mock.address(), Duration::from_millis(300))
        .open_udp(Target::Ip(DOC_IPV4.into()), 53, &audit)
        .unwrap();
    udp.send(b"x").unwrap();
    let started = Instant::now();
    let error = udp.recv().unwrap_err();
    assert!(matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ));
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the UDP wait was not bounded"
    );
    drop(udp);

    assert_eq!(audit.snapshot(), (1, 0));
    mock.stop().assert_clean();
}

#[test]
fn source_close_after_connect_is_eof_and_stop_closes_the_listener() {
    let mut mock = MockSocksSource::start(SocksConfig {
        payload: SocksPayload::CloseTcp,
        ..Default::default()
    })
    .unwrap();
    let address = mock.address();
    let audit = Audit::default();
    let mut stream = proxy(address, Duration::from_secs(2))
        .open_tcp(Target::Domain(TEST_DOMAIN), 443, &audit)
        .unwrap();
    let mut byte = [0u8; 1];
    assert_eq!(stream.read(&mut byte).unwrap(), 0);
    drop(stream);

    assert_eq!(audit.snapshot(), (1, 0));
    let report = mock.stop();
    report.assert_clean();
    assert!(
        std::net::TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_err(),
        "the mock listener must be closed after stop"
    );
}
