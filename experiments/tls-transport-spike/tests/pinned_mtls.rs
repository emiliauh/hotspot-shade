//! Happy path: pinned server identity, mutual client authentication, TLS 1.3.

mod support;

use std::sync::atomic::Ordering;

use rustls::client::danger::ServerCertVerifier;
use rustls::server::danger::ClientCertVerifier;
use rustls::HandshakeKind;
use support::{connect, spawn_sessions};
use tls_transport_spike::transport::{
    client_config, client_config_cert_pin, pinned_client_verifier, pinned_server_verifier,
    policy_signature_schemes, read_exact_plain, server_config, write_plain, PinKind,
};
use tls_transport_spike::{Pin, TestIdentity};

#[test]
fn pinned_server_and_mutual_client_auth() {
    let server = TestIdentity::server();
    let client = TestIdentity::client();
    let server_tls = server_config(&server, client.spki_pin);
    let client_checks = server_tls.client_cert_checks.clone();
    let client_tls = client_config(&client, server.spki_pin);

    let server = spawn_sessions(server_tls.config, 1, |_, stream, conn| {
        // The client passes an IP address as its server name, so rustls sends
        // no SNI extension. A product-specific host name would be a
        // fingerprint and the pin is the trust decision.
        assert_eq!(conn.server_name(), None, "client must not send SNI");
        let mut greeting = [0u8; 5];
        read_exact_plain(conn, stream, &mut greeting)?;
        assert_eq!(&greeting, b"hello");
        assert_eq!(
            conn.handshake_kind(),
            Some(HandshakeKind::Full),
            "the default config must not resume"
        );
        write_plain(conn, stream, b"world")?;
        Ok(())
    });

    let (mut stream, mut conn) = connect(server.port, client_tls).expect("client handshake");
    assert_eq!(
        format!(
            "{:?}",
            conn.negotiated_cipher_suite().expect("cipher suite")
        )
        .split('_')
        .next(),
        Some("TLS13"),
        "cipher suite must be a TLS 1.3 suite"
    );
    assert_eq!(conn.peer_certificates().expect("peer certificate").len(), 1);
    assert_eq!(
        conn.handshake_kind(),
        Some(HandshakeKind::Full),
        "the default config must not resume"
    );

    write_plain(&mut conn, &mut stream, b"hello").expect("client write");
    let mut reply = [0u8; 5];
    read_exact_plain(&mut conn, &mut stream, &mut reply).expect("client read");
    assert_eq!(&reply, b"world");

    let results = server.finish();
    results[0].as_ref().expect("server session must succeed");
    assert_eq!(
        client_checks.load(Ordering::SeqCst),
        1,
        "server must check the pinned client identity once"
    );
}

#[test]
fn certificate_pin_accepts_the_same_leaf() {
    let server = TestIdentity::server();
    let client = TestIdentity::client();
    let server_tls = server_config(&server, client.spki_pin);
    let checks = server_tls.client_cert_checks.clone();
    let client_tls = client_config_cert_pin(&client, server.cert_pin);

    let server = spawn_sessions(server_tls.config, 1, |_, stream, conn| {
        write_plain(conn, stream, b"ok")?;
        Ok(())
    });

    let (mut stream, mut conn) = connect(server.port, client_tls).expect("client handshake");
    let mut reply = [0u8; 2];
    read_exact_plain(&mut conn, &mut stream, &mut reply).expect("client read");
    assert_eq!(&reply, b"ok");

    server.finish()[0].as_ref().expect("server session");
    assert_eq!(checks.load(Ordering::SeqCst), 1);
}

#[test]
fn two_connections_have_independent_tls_sessions() {
    let server = TestIdentity::server();
    let client = TestIdentity::client();
    let server_tls = server_config(&server, client.spki_pin);
    let checks = server_tls.client_cert_checks.clone();

    let sessions = spawn_sessions(server_tls.config, 2, |index, stream, conn| {
        write_plain(conn, stream, &[index as u8])?;
        Ok(conn.handshake_kind())
    });

    let mut observed = Vec::new();
    for _ in 0..2 {
        let client_tls = client_config(&client, server.spki_pin);
        let (mut stream, mut conn) = connect(sessions.port, client_tls).expect("client handshake");
        let mut byte = [0u8; 1];
        read_exact_plain(&mut conn, &mut stream, &mut byte).expect("client read");
        observed.push(byte[0]);
        assert_eq!(
            conn.handshake_kind(),
            Some(HandshakeKind::Full),
            "the default config must run a full handshake each time"
        );
    }
    observed.sort();
    assert_eq!(observed, vec![0, 1]);

    for result in sessions.finish() {
        assert_eq!(
            result.expect("each server session must succeed on its own connection"),
            Some(HandshakeKind::Full)
        );
    }
    assert_eq!(checks.load(Ordering::SeqCst), 2);
}

#[test]
fn verifiers_advertise_only_the_p256_policy() {
    let client_verifier = pinned_client_verifier(Pin::of_spki(b"fixed public bytes"));
    assert_eq!(
        client_verifier.supported_verify_schemes(),
        policy_signature_schemes(),
        "client-certificate verifier must advertise exactly the tested policy"
    );

    let server_verifier =
        pinned_server_verifier(Pin::of_spki(b"fixed public bytes"), PinKind::Spki);
    assert_eq!(
        server_verifier.supported_verify_schemes(),
        policy_signature_schemes(),
        "server-certificate verifier must advertise exactly the tested policy"
    );
    assert_eq!(
        policy_signature_schemes(),
        vec![rustls::SignatureScheme::ECDSA_NISTP256_SHA256]
    );
}
