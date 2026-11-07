//! Signature policy tests.
//!
//! The verifiers advertise only ECDSA P-256 with SHA-256. Two layers enforce
//! that:
//!
//! - the advertisement removes other schemes from the ClientHello and the
//!   CertificateRequest, so a conforming peer cannot select one;
//! - `reject_disallowed_scheme` refuses any other scheme that arrives on the
//!   wire before the provider checks the signature.
//!
//! A conforming rustls peer will not send a scheme outside the advertisement,
//! so the direct check is exercised with a test-only signer that ignores the
//! advertised list. The P-384 identity tests show the advertisement itself.

mod support;

use std::sync::atomic::Ordering;

use support::{connect, connect_unchecked, spawn_sessions};
use tls_transport_spike::transport::{
    client_config, client_config_with_checks, client_config_with_forced_signature_scheme,
    server_config, server_config_with_forced_signature_scheme,
};
use tls_transport_spike::TestIdentity;

const POLICY_ERROR: &str = "outside this spike's ECDSA P-256 policy";

#[test]
fn client_signature_outside_the_policy_is_rejected_by_the_server() {
    let server = TestIdentity::server();
    let client = TestIdentity::client();
    let server_tls = server_config(&server, client.spki_pin);
    let server_checks = server_tls.client_cert_checks.clone();
    let client_tls = client_config_with_forced_signature_scheme(
        &client,
        rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
        server.spki_pin,
    );

    let sessions = spawn_sessions(server_tls.config, 1, |_, _, _| Ok(()));
    // The client may finish its side before the server processes the
    // CertificateVerify. The server error is the required outcome.
    let _ = connect(sessions.port, client_tls);

    let results = sessions.finish();
    let server_error = results[0]
        .as_ref()
        .expect_err("the server must reject a signature scheme outside the policy");
    assert!(
        server_error.to_string().contains(POLICY_ERROR),
        "unexpected server error: {server_error}"
    );
    assert_eq!(
        server_checks.load(Ordering::SeqCst),
        1,
        "the pin check must run before the scheme check"
    );
}

#[test]
fn server_signature_outside_the_policy_is_rejected_by_the_client() {
    let server = TestIdentity::server();
    let client = TestIdentity::client();
    let server_tls = server_config_with_forced_signature_scheme(
        &server,
        rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
        client.spki_pin,
    );
    let client_tls = client_config_with_checks(&client, server.spki_pin);
    let server_checks = client_tls.server_cert_checks.clone();

    let sessions = spawn_sessions(server_tls.config, 1, |_, _, _| Ok(()));
    let error = connect(sessions.port, client_tls.config)
        .expect_err("the client must reject a signature scheme outside the policy");
    assert!(
        error.to_string().contains(POLICY_ERROR),
        "unexpected client error: {error}"
    );
    assert_eq!(
        server_checks.load(Ordering::SeqCst),
        1,
        "the pin check must run before the scheme check"
    );
    let _ = sessions.finish();
}

#[test]
fn p384_server_identity_cannot_negotiate_under_the_p256_policy() {
    let server = TestIdentity::server_p384();
    let client = TestIdentity::client();
    let server_tls = server_config(&server, client.spki_pin);
    let client_tls = client_config(&client, server.spki_pin);

    let sessions = spawn_sessions(server_tls.config, 1, |_, _, _| Ok(()));
    connect_unchecked(sessions.port, client_tls)
        .expect_err("a P-384 server key cannot satisfy a P-256-only client policy");

    let results = sessions.finish();
    let server_error = results[0]
        .as_ref()
        .expect_err("the server cannot pick a signature scheme under the policy");
    let message = server_error.to_string().to_lowercase();
    assert!(
        message.contains("signature") || message.contains("algorithm"),
        "unexpected server error: {server_error}"
    );
}

#[test]
fn p384_client_identity_cannot_authenticate_under_the_p256_policy() {
    let server = TestIdentity::server();
    let client = TestIdentity::client_p384();
    let server_tls = server_config(&server, client.spki_pin);
    let client_tls = client_config(&client, server.spki_pin);

    let sessions = spawn_sessions(server_tls.config, 1, |_, _, _| Ok(()));
    // The client has a P-384 key and the server asks only for P-256, so the
    // client sends an empty certificate message.
    let _ = connect(sessions.port, client_tls);

    let results = sessions.finish();
    let server_error = results[0]
        .as_ref()
        .expect_err("a P-384 client identity cannot satisfy the P-256 policy");
    let message = server_error.to_string().to_lowercase();
    assert!(
        message.contains("certificate") || message.contains("signature"),
        "unexpected server error: {server_error}"
    );
}
