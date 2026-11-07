//! ALPN policy, enforced by the library rather than by this test harness.
//!
//! rustls rejects a client whose ALPN list does not overlap the server list
//! with a `no_application_protocol` alert. It does not reject a client that
//! sends no ALPN extension, and a client accepts a server that selects nothing.
//! The spike closes both gaps in `src/transport.rs`:
//!
//! - `accept_server` reads the ClientHello and requires the spike label, which
//!   also rejects a list that holds only other labels.
//! - `handshake_server` and `handshake_client` require the negotiated label.

mod support;

use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;

use support::{
    accept_with_deadline, connect, connect_unchecked, spawn_sessions, ClientConfig, ServerConfig,
    ServerConnection,
};
use tls_transport_spike::transport::{
    client_config, client_config_with_alpn, client_config_without_alpn, handshake_server,
    new_client_connection, require_negotiated_alpn, server_config, server_config_without_alpn,
    tune, HandshakeDeadline, ALPN,
};
use tls_transport_spike::TestIdentity;

#[test]
fn client_without_alpn_is_rejected_by_the_library_acceptor() {
    let server = TestIdentity::server();
    let client = TestIdentity::client();
    let server_tls = server_config(&server, client.spki_pin);
    let client_checks = server_tls.client_cert_checks.clone();
    let client_tls = client_config_without_alpn(&client, server.spki_pin);

    let sessions = spawn_sessions(server_tls.config, 1, |_, _, _| Ok(()));
    connect_unchecked(sessions.port, client_tls)
        .expect_err("a client with no ALPN extension must be rejected");

    let results = sessions.finish();
    let server_error = results[0]
        .as_ref()
        .expect_err("the acceptor must reject a client with no ALPN");
    assert!(
        server_error
            .to_string()
            .contains("did not offer the required ALPN label"),
        "unexpected server error: {server_error}"
    );
    assert_eq!(
        client_checks.load(Ordering::SeqCst),
        0,
        "the server must reject the ClientHello before it builds a connection"
    );
}

#[test]
fn client_with_only_a_non_matching_alpn_is_rejected_by_the_library_acceptor() {
    let server = TestIdentity::server();
    let client = TestIdentity::client();
    let server_tls = server_config(&server, client.spki_pin);
    let client_tls = client_config_with_alpn(&client, server.spki_pin, b"proxy/0");

    let sessions = spawn_sessions(server_tls.config, 1, |_, _, _| Ok(()));
    connect_unchecked(sessions.port, client_tls)
        .expect_err("a client with only a non-matching ALPN label must be rejected");

    let results = sessions.finish();
    let server_error = results[0]
        .as_ref()
        .expect_err("the acceptor must reject a non-matching ALPN list");
    assert!(
        server_error
            .to_string()
            .contains("did not offer the required ALPN label"),
        "unexpected server error: {server_error}"
    );
}

#[test]
fn server_connection_built_without_the_acceptor_rejects_a_non_matching_label() {
    // Bypass the ClientHello presence check and let rustls see a non-overlapping
    // list. This is the documented rustls behavior: a fatal
    // `no_application_protocol` alert.
    let server = TestIdentity::server();
    let client = TestIdentity::client();
    let server_tls = server_config(&server, client.spki_pin);
    let client_tls = client_config_with_alpn(&client, server.spki_pin, b"proxy/0");

    let (client_result, server_result) = direct_server_handshake(client_tls, server_tls.config);
    let server_error = server_result.expect_err("rustls must reject a non-matching ALPN list");
    assert!(
        server_error.to_string().contains("known protocol"),
        "rustls should report the no_application_protocol alert, got: {server_error}"
    );
    // The client learns about the rejection during the handshake or on its
    // first read. Either is a rejection.
    let _ = client_result;
}

#[test]
fn server_that_selects_no_alpn_is_rejected_by_the_client() {
    let server = TestIdentity::server();
    let client = TestIdentity::client();
    let server_tls = server_config_without_alpn(&server, client.spki_pin);
    let client_tls = client_config(&client, server.spki_pin);

    let sessions = spawn_sessions(server_tls.config, 1, |_, _, _| Ok(()));
    let error = connect(sessions.port, client_tls)
        .expect_err("a server that selects no ALPN must be rejected by the client");

    assert!(
        error
            .to_string()
            .contains("did not negotiate the required ALPN label"),
        "unexpected client error: {error}"
    );

    let results = sessions.finish();
    let server_error = results[0]
        .as_ref()
        .expect_err("the server library must also reject the missing selection");
    assert!(
        server_error
            .to_string()
            .contains("did not negotiate the required ALPN label"),
        "unexpected server error: {server_error}"
    );
}

#[test]
fn server_connection_built_without_the_acceptor_still_rejects_missing_alpn() {
    // A caller can build a `ServerConnection` directly and skip the ClientHello
    // check. The post-handshake check must still reject the connection.
    let server = TestIdentity::server();
    let client = TestIdentity::client();
    let server_tls = server_config(&server, client.spki_pin);
    let client_tls = client_config_without_alpn(&client, server.spki_pin);

    let (_, server_result) = direct_server_handshake(client_tls, server_tls.config);
    let server_error =
        server_result.expect_err("the server library must reject a connection with no ALPN");
    assert!(
        server_error
            .to_string()
            .contains("did not negotiate the required ALPN label"),
        "unexpected server error: {server_error}"
    );
}

#[test]
fn only_the_policy_label_is_accepted() {
    assert!(require_negotiated_alpn(Some(ALPN)).is_ok());
    assert!(require_negotiated_alpn(None).is_err());
    assert!(require_negotiated_alpn(Some(b"proxy/0")).is_err());
    assert!(require_negotiated_alpn(Some(b"")).is_err());
}

/// Run one handshake where the server builds its connection directly instead of
/// through `accept_server`, and where the client drives rustls without the
/// library post-check. Returns the client and server results.
fn direct_server_handshake(
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
) -> (io::Result<()>, io::Result<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let port = listener
        .local_addr()
        .expect("listener local address")
        .port();
    let worker = thread::spawn(move || {
        let mut stream = accept_with_deadline(&listener)?;
        tune(&stream)?;
        let mut conn = ServerConnection::new(server_config)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        handshake_server(&mut conn, &mut stream, &HandshakeDeadline::default_policy())
    });

    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("raw loopback connect");
    tune(&stream).expect("client socket options");
    let mut conn = new_client_connection(client_config).expect("client connection");
    let client_result = conn.complete_io(&mut stream).map(|_| ());
    let server_result = worker.join().expect("server worker did not panic");
    (client_result, server_result)
}
