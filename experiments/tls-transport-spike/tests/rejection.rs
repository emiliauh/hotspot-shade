//! Rejection cases: wrong server, wrong client, a pinned certificate with the
//! wrong signing key, anonymous client, cleartext, a plaintext server, and
//! replayed TLS records. ALPN rejection lives in `tests/alpn.rs`.

mod support;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use support::{connect, connect_raw, payload, spawn_sessions, ClientConfig};
use tls_transport_spike::transport::{
    client_config, client_config_with_checks, client_config_with_mismatched_key,
    client_config_with_unchecked_signing_key, client_config_without_cert,
    first_application_data_record, flush_client_records, read_chunk_plain, read_exact_plain,
    server_config, server_config_mismatched_signing_key, write_plain, IO_TIMEOUT,
};
use tls_transport_spike::TestIdentity;

/// A rejected client can learn about the rejection either during the
/// handshake or on the first read, because a TLS 1.3 client sends its Finished
/// before the server has processed its certificate. Both count as rejection;
/// the server side must always report an error.
fn expect_client_rejected(port: u16, config: std::sync::Arc<ClientConfig>) -> std::io::Error {
    match connect(port, config) {
        Err(error) => error,
        Ok((mut stream, mut conn)) => {
            let _ = write_plain(&mut conn, &mut stream, b"x");
            let mut buf = [0u8; 1];
            read_exact_plain(&mut conn, &mut stream, &mut buf)
                .expect_err("client must observe rejection on the first read")
        }
    }
}

#[test]
fn wrong_server_identity_is_rejected_before_the_client_certificate() {
    let pinned_server = TestIdentity::server();
    let impostor = TestIdentity::server();
    let client = TestIdentity::client();

    let server_tls = server_config(&impostor, client.spki_pin);
    let client_checks = server_tls.client_cert_checks.clone();
    let client_tls = client_config(&client, pinned_server.spki_pin);

    let sessions = spawn_sessions(server_tls.config, 1, |_, _, _| Ok(()));
    let error = connect(sessions.port, client_tls).expect_err("wrong server must be rejected");
    assert!(
        error
            .to_string()
            .contains("server certificate pin mismatch"),
        "unexpected client error: {error}"
    );

    let results = sessions.finish();
    assert!(results[0].is_err(), "server must see a handshake abort");
    assert_eq!(
        client_checks.load(Ordering::SeqCst),
        0,
        "client must abort before it sends its certificate to a wrong server"
    );
}

#[test]
fn wrong_client_identity_is_rejected() {
    let server = TestIdentity::server();
    let pinned_client = TestIdentity::client();
    let other_client = TestIdentity::client();

    let server_tls = server_config(&server, pinned_client.spki_pin);
    let client_tls = client_config(&other_client, server.spki_pin);
    let sessions = spawn_sessions(server_tls.config, 1, |_, _, _| Ok(()));
    let client_error = expect_client_rejected(sessions.port, client_tls);
    assert!(
        client_error.to_string().to_lowercase().contains("alert")
            || client_error.to_string().to_lowercase().contains("eof"),
        "client should receive a TLS alert or an early close, got: {client_error}"
    );

    let results = sessions.finish();
    let server_error = results[0]
        .as_ref()
        .expect_err("server must reject the unpinned client certificate");
    assert!(
        server_error
            .to_string()
            .contains("client certificate SPKI pin mismatch"),
        "unexpected server error: {server_error}"
    );
}

#[test]
fn certificate_without_the_matching_private_key_is_rejected_by_the_config_builder() {
    let server = TestIdentity::server();
    let pinned_client = TestIdentity::client();
    let other_key = TestIdentity::client();

    // The pin matches the presented certificate, but the private key does not.
    // rustls refuses to build this client configuration at all, before any
    // connection exists. This is the configuration-builder check, not the
    // handshake check; the next test bypasses it with a custom resolver.
    let result = client_config_with_mismatched_key(&pinned_client, &other_key, server.spki_pin);
    let error = result.expect_err("a certificate and an unrelated key must be refused");
    assert!(
        error.to_string().to_lowercase().contains("key"),
        "unexpected configuration error: {error}"
    );
}

#[test]
fn pinned_client_certificate_with_wrong_signing_key_fails_certificate_verify() {
    let server = TestIdentity::server();
    let pinned_client = TestIdentity::client();
    let other_key = TestIdentity::client();

    let server_tls = server_config(&server, pinned_client.spki_pin);
    let client_checks = server_tls.client_cert_checks.clone();
    // The resolver returns the pinned certificate with a different key, so the
    // configuration builder cannot reject it. The server must reject the
    // CertificateVerify signature after the pin check passes.
    let client_tls =
        client_config_with_unchecked_signing_key(&pinned_client, &other_key, server.spki_pin);
    let sessions = spawn_sessions(server_tls.config, 1, |_, _, _| Ok(()));

    let client_error = expect_client_rejected(sessions.port, client_tls);
    assert!(
        !client_error.to_string().is_empty(),
        "client must observe a failure"
    );

    let results = sessions.finish();
    let server_error = results[0]
        .as_ref()
        .expect_err("server must reject a signature from the wrong key");
    let lower = server_error.to_string().to_lowercase();
    assert!(
        lower.contains("signature"),
        "unexpected server error: {server_error}"
    );
    assert_eq!(
        client_checks.load(Ordering::SeqCst),
        1,
        "the pin check must run before CertificateVerify fails"
    );
}

#[test]
fn pinned_server_certificate_with_wrong_signing_key_fails_certificate_verify() {
    let pinned_server = TestIdentity::server();
    let other_key = TestIdentity::server();
    let client = TestIdentity::client();

    let server_tls =
        server_config_mismatched_signing_key(&pinned_server, &other_key, client.spki_pin);
    // The client pins the certificate that the server presents. The pin check
    // passes; the CertificateVerify signature must fail.
    let client_tls = client_config_with_checks(&client, pinned_server.spki_pin);
    let server_checks = client_tls.server_cert_checks.clone();
    let sessions = spawn_sessions(server_tls.config, 1, |_, _, _| Ok(()));

    let error = connect(sessions.port, client_tls.config)
        .expect_err("client must reject a signature from the wrong key");
    let lower = error.to_string().to_lowercase();
    assert!(
        lower.contains("signature"),
        "unexpected client error: {error}"
    );
    assert_eq!(
        server_checks.load(Ordering::SeqCst),
        1,
        "the pin check must run before CertificateVerify fails"
    );

    let results = sessions.finish();
    assert!(
        results[0].is_err(),
        "server must see the client abort after a bad signature"
    );
}

#[test]
fn anonymous_client_is_rejected() {
    let server = TestIdentity::server();
    let pinned_client = TestIdentity::client();
    let server_tls = server_config(&server, pinned_client.spki_pin);
    let client_tls = client_config_without_cert(server.spki_pin);

    let sessions = spawn_sessions(server_tls.config, 1, |_, _, _| Ok(()));
    expect_client_rejected(sessions.port, client_tls);
    let results = sessions.finish();
    assert!(
        results[0].is_err(),
        "server must reject an anonymous client"
    );
}

#[test]
fn cleartext_to_the_tls_listener_is_rejected() {
    let server = TestIdentity::server();
    let client = TestIdentity::client();
    let server_tls = server_config(&server, client.spki_pin);
    let sessions = spawn_sessions(server_tls.config, 1, |_, _, _| Ok(()));

    let mut raw = connect_raw(sessions.port).expect("raw loopback connect");
    raw.write_all(b"GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n")
        .expect("raw write");

    let mut received = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        match raw.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => received.extend_from_slice(&buf[..n]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("raw read failed: {error}"),
        }
    }
    assert!(
        !received.windows(4).any(|window| window == b"HTTP"),
        "TLS listener must not answer cleartext HTTP"
    );

    let results = sessions.finish();
    assert!(
        results[0].is_err(),
        "server must fail the handshake on cleartext input"
    );
}

#[test]
fn plaintext_server_is_rejected_by_the_pinned_client() {
    let server_identity = TestIdentity::server();
    let client = TestIdentity::client();

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake server");
    let port = listener.local_addr().expect("local address").port();
    let fake = thread::spawn(move || {
        // Bound the accept so a failed client connection cannot hang the test.
        let mut stream = support::accept_with_deadline(&listener).expect("accept client");
        stream
            .set_write_timeout(Some(IO_TIMEOUT))
            .expect("fake server write timeout");
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .expect("fake server read timeout");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .expect("write plaintext");
        // Drop closes the socket.
    });

    let client_tls = client_config(&client, server_identity.spki_pin);
    connect(port, client_tls).expect_err("plaintext server must fail the TLS handshake");
    fake.join().expect("fake server thread");
}

#[derive(Debug)]
struct ReplayOutcome {
    plaintext_bytes: usize,
    error: Option<String>,
}

#[test]
fn replayed_application_record_is_rejected_on_a_fresh_connection() {
    let server = TestIdentity::server();
    let client = TestIdentity::client();
    let server_tls = server_config(&server, client.spki_pin);
    let message = b"replay-me-000001";
    let (server_ready_tx, server_ready_rx) = mpsc::channel::<()>();
    let (inject_tx, inject_rx) = mpsc::channel::<()>();
    let inject_rx = Arc::new(Mutex::new(inject_rx));

    let sessions = spawn_sessions(server_tls.config, 2, {
        let inject_rx = inject_rx.clone();
        move |index, stream, conn| {
            if index == 0 {
                let mut received = [0u8; 16];
                read_exact_plain(conn, stream, &mut received)?;
                assert_eq!(&received, message);
                write_plain(conn, stream, &received)?;
                return Ok(ReplayOutcome {
                    plaintext_bytes: received.len(),
                    error: None,
                });
            }

            // Tell the test that this TLS handshake has finished, then wait for
            // permission to inject the record. Both waits are bounded: a
            // missing client fails after the timeout instead of hanging.
            server_ready_tx
                .send(())
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "ready"))?;
            let receiver = inject_rx.lock().expect("replay signal lock");
            receiver.recv_timeout(IO_TIMEOUT).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "replay signal did not arrive")
            })?;

            let mut buf = [0u8; 64];
            match read_chunk_plain(conn, stream, &mut buf) {
                Ok(n) => Ok(ReplayOutcome {
                    plaintext_bytes: n,
                    error: None,
                }),
                Err(error) => Ok(ReplayOutcome {
                    plaintext_bytes: 0,
                    error: Some(error.to_string()),
                }),
            }
        }
    });

    // Session one records one application-data record from the wire.
    let (mut stream, mut conn) = connect(sessions.port, client_config(&client, server.spki_pin))
        .expect("first client handshake");
    conn.writer()
        .write_all(message)
        .expect("buffer first message");
    let wire = flush_client_records(&mut conn, &mut stream).expect("flush first message");
    let record = first_application_data_record(&wire).expect("application-data record");
    assert_eq!(record[0], 23, "record must be application data");
    assert_ne!(
        &record[5..],
        message.as_slice(),
        "application data must be encrypted on the wire"
    );
    let mut echo = [0u8; 16];
    read_exact_plain(&mut conn, &mut stream, &mut echo).expect("first echo");
    assert_eq!(&echo, message);

    // Session two replays the captured record into a new TLS connection.
    let (mut stream, _conn) = connect(sessions.port, client_config(&client, server.spki_pin))
        .expect("second client handshake");
    server_ready_rx
        .recv_timeout(IO_TIMEOUT)
        .expect("second server session reached its handler");
    inject_tx.send(()).expect("release second server session");
    stream.write_all(&record).expect("inject replayed record");

    let results = sessions.finish();
    let first = results[0].as_ref().expect("first session must succeed");
    assert_eq!(first.plaintext_bytes, message.len());

    let second = results[1].as_ref().expect("second session handler ran");
    assert_eq!(
        second.plaintext_bytes, 0,
        "replayed record must yield no plaintext"
    );
    let error = second
        .error
        .as_deref()
        .expect("replay must produce an error");
    assert!(
        error.to_lowercase().contains("decrypt")
            || error.to_lowercase().contains("alert")
            || error.to_lowercase().contains("invalid"),
        "unexpected replay error: {error}"
    );
}

#[test]
fn payload_helper_is_deterministic() {
    // Guards the byte-exact test data against an accidental change that makes
    // the connection test compare the same buffer to itself.
    assert_eq!(payload(32), payload(32));
    assert_ne!(payload(32), payload(33));
}
