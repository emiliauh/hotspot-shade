//! Session resumption behavior.
//!
//! The spike policy sends no TLS 1.3 tickets and disables client session
//! storage, so every connection runs the full handshake and both pin checks.
//! These tests also build a deliberately resumable pair to show what changes:
//! the second handshake is resumed and neither verifier runs. That is why the
//! default policy disables resumption.

mod support;

use std::sync::atomic::Ordering;

use rustls::HandshakeKind;
use support::{connect, spawn_sessions};
use tls_transport_spike::transport::{
    client_config_resumable_with_checks, client_config_with_checks, read_exact_plain,
    server_config, server_config_resumable, write_plain,
};
use tls_transport_spike::TestIdentity;

#[test]
fn default_config_sends_no_tickets_and_never_resumes() {
    let server = TestIdentity::server();
    let client = TestIdentity::client();
    let server_tls = server_config(&server, client.spki_pin);
    assert_eq!(
        server_tls.config.send_tls13_tickets, 0,
        "default server config must not send session tickets"
    );
    let server_checks = server_tls.client_cert_checks.clone();
    let client_tls = client_config_with_checks(&client, server.spki_pin);
    let client_checks = client_tls.server_cert_checks.clone();

    let sessions = spawn_sessions(server_tls.config, 2, |_, stream, conn| {
        write_plain(conn, stream, b"x")?;
        Ok(conn.handshake_kind())
    });

    // The same client config is shared across both connections. Even so, the
    // disabled session store must not produce a resumed session.
    for _ in 0..2 {
        let (mut stream, mut conn) =
            connect(sessions.port, client_tls.config.clone()).expect("client handshake");
        let mut byte = [0u8; 1];
        read_exact_plain(&mut conn, &mut stream, &mut byte).expect("client read");
        assert_eq!(
            conn.handshake_kind(),
            Some(HandshakeKind::Full),
            "default config must run a full handshake"
        );
    }

    for result in sessions.finish() {
        assert_eq!(result.expect("server session"), Some(HandshakeKind::Full));
    }
    assert_eq!(
        server_checks.load(Ordering::SeqCst),
        2,
        "server pin check must run on every full handshake"
    );
    assert_eq!(
        client_checks.load(Ordering::SeqCst),
        2,
        "client pin check must run on every full handshake"
    );
}

#[test]
fn resumable_pair_resumes_and_skips_both_pin_checks() {
    let server = TestIdentity::server();
    let client = TestIdentity::client();
    let server_tls = server_config_resumable(&server, client.spki_pin);
    assert_eq!(server_tls.config.send_tls13_tickets, 2);
    let server_checks = server_tls.client_cert_checks.clone();
    let client_tls = client_config_resumable_with_checks(&client, server.spki_pin);
    let client_checks = client_tls.server_cert_checks.clone();

    let sessions = spawn_sessions(server_tls.config, 2, |_, stream, conn| {
        // Flushing application data also flushes the queued NewSessionTicket.
        write_plain(conn, stream, b"x")?;
        Ok(conn.handshake_kind())
    });

    let mut client_kinds = Vec::new();
    for _ in 0..2 {
        let (mut stream, mut conn) =
            connect(sessions.port, client_tls.config.clone()).expect("client handshake");
        let mut byte = [0u8; 1];
        read_exact_plain(&mut conn, &mut stream, &mut byte).expect("client read");
        client_kinds.push(conn.handshake_kind());
    }

    assert_eq!(client_kinds[0], Some(HandshakeKind::Full));
    assert_eq!(
        client_kinds[1],
        Some(HandshakeKind::Resumed),
        "the second connection must resume"
    );

    let server_kinds: Vec<_> = sessions
        .finish()
        .into_iter()
        .map(|result| result.expect("server session"))
        .collect();
    assert_eq!(server_kinds[0], Some(HandshakeKind::Full));
    assert_eq!(server_kinds[1], Some(HandshakeKind::Resumed));

    // A resumed TLS 1.3 handshake does not carry a certificate message, so the
    // verifiers do not run. This is the reason the default config disables
    // resumption: a pin change after ticket issuance would not apply to a
    // resumed session.
    assert_eq!(
        server_checks.load(Ordering::SeqCst),
        1,
        "server pin check must not run on the resumed session"
    );
    assert_eq!(
        client_checks.load(Ordering::SeqCst),
        1,
        "client pin check must not run on the resumed session"
    );
}

#[test]
fn ticket_sending_server_with_a_non_resuming_client_stays_full() {
    // One side alone cannot create a resumed session. The server offers tickets
    // and the client refuses to store them.
    let server = TestIdentity::server();
    let client = TestIdentity::client();
    let server_tls = server_config_resumable(&server, client.spki_pin);
    assert_eq!(server_tls.config.send_tls13_tickets, 2);
    let server_checks = server_tls.client_cert_checks.clone();
    let client_tls = client_config_with_checks(&client, server.spki_pin);
    let client_checks = client_tls.server_cert_checks.clone();

    let sessions = spawn_sessions(server_tls.config, 2, |_, stream, conn| {
        // Flushing application data also flushes a queued ticket.
        write_plain(conn, stream, b"x")?;
        Ok(conn.handshake_kind())
    });

    for _ in 0..2 {
        let (mut stream, mut conn) =
            connect(sessions.port, client_tls.config.clone()).expect("client handshake");
        let mut byte = [0u8; 1];
        read_exact_plain(&mut conn, &mut stream, &mut byte).expect("client read");
        assert_eq!(
            conn.handshake_kind(),
            Some(HandshakeKind::Full),
            "a client with resumption disabled must not resume"
        );
    }

    for result in sessions.finish() {
        assert_eq!(
            result.expect("server session"),
            Some(HandshakeKind::Full),
            "the server must also report a full handshake"
        );
    }
    assert_eq!(
        server_checks.load(Ordering::SeqCst),
        2,
        "the server pin check must run on both full handshakes"
    );
    assert_eq!(
        client_checks.load(Ordering::SeqCst),
        2,
        "the client pin check must run on both full handshakes"
    );
}

#[test]
fn ticket_accepting_client_with_a_non_ticket_server_never_resumes() {
    // The client is willing to store a ticket, but the server sends none, so
    // there is nothing to resume from.
    let server = TestIdentity::server();
    let client = TestIdentity::client();
    let server_tls = server_config(&server, client.spki_pin);
    assert_eq!(server_tls.config.send_tls13_tickets, 0);
    let server_checks = server_tls.client_cert_checks.clone();
    let client_tls = client_config_resumable_with_checks(&client, server.spki_pin);
    let client_checks = client_tls.server_cert_checks.clone();

    let sessions = spawn_sessions(server_tls.config, 2, |_, stream, conn| {
        write_plain(conn, stream, b"x")?;
        Ok(conn.handshake_kind())
    });

    for _ in 0..2 {
        let (mut stream, mut conn) =
            connect(sessions.port, client_tls.config.clone()).expect("client handshake");
        let mut byte = [0u8; 1];
        read_exact_plain(&mut conn, &mut stream, &mut byte).expect("client read");
        assert_eq!(
            conn.handshake_kind(),
            Some(HandshakeKind::Full),
            "a client cannot resume without a ticket"
        );
    }

    for result in sessions.finish() {
        assert_eq!(
            result.expect("server session"),
            Some(HandshakeKind::Full),
            "the server must report a full handshake"
        );
    }
    assert_eq!(
        server_checks.load(Ordering::SeqCst),
        2,
        "the server pin check must run on both full handshakes"
    );
    assert_eq!(
        client_checks.load(Ordering::SeqCst),
        2,
        "the client pin check must run on both full handshakes"
    );
}
