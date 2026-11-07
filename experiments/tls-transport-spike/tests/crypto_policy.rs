//! The crypto policy the configuration actually gets from the ring provider.
//!
//! The spike does not hand-pick a cipher suite or a key exchange group. Both
//! configs use the provider's default list, so the list below is the policy.
//! These tests make a dependency change that alters that list visible, and they
//! record which values a loopback handshake selects in practice.

mod support;

use rustls::crypto::ring::default_provider;
use rustls::{CipherSuite, NamedGroup, ProtocolVersion, SignatureScheme};
use support::{connect, spawn_sessions};
use tls_transport_spike::transport::{
    client_config, policy_signature_schemes, server_config, ALPN,
};
use tls_transport_spike::TestIdentity;

fn cipher_names() -> Vec<String> {
    default_provider()
        .cipher_suites
        .iter()
        .map(|suite| format!("{:?}", suite.suite()))
        .collect()
}

fn group_names() -> Vec<String> {
    default_provider()
        .kx_groups
        .iter()
        .map(|group| format!("{:?}", group.name()))
        .collect()
}

#[test]
fn provider_offers_only_the_three_tls13_cipher_suites() {
    assert_eq!(
        cipher_names(),
        vec![
            "TLS13_AES_256_GCM_SHA384".to_string(),
            "TLS13_AES_128_GCM_SHA256".to_string(),
            "TLS13_CHACHA20_POLY1305_SHA256".to_string(),
        ],
        "the tls12 feature is off, so only TLS 1.3 suites are built"
    );
    assert!(
        default_provider()
            .cipher_suites
            .iter()
            .all(|suite| suite.tls13().is_some()),
        "no TLS 1.2 suite may be enabled"
    );
}

#[test]
fn provider_key_exchange_groups_are_the_documented_set() {
    assert_eq!(
        group_names(),
        vec![
            "X25519".to_string(),
            "secp256r1".to_string(),
            "secp384r1".to_string(),
        ],
        "these are the ring provider's default groups"
    );
}

#[test]
fn provider_signature_algorithms_are_wider_than_the_policy() {
    let provider = default_provider();
    let provider_schemes = provider
        .signature_verification_algorithms
        .supported_schemes();
    assert!(
        provider_schemes.len() > 1,
        "the provider supports more handshake signature schemes than the policy"
    );
    assert!(provider_schemes.contains(&SignatureScheme::ECDSA_NISTP256_SHA256));
    assert!(provider_schemes.contains(&SignatureScheme::ED25519));

    assert_eq!(
        policy_signature_schemes(),
        vec![SignatureScheme::ECDSA_NISTP256_SHA256],
        "the spike policy advertises exactly one signature scheme"
    );
}

#[test]
fn loopback_handshake_selects_documented_values() {
    let server = TestIdentity::server();
    let client = TestIdentity::client();
    let server_tls = server_config(&server, client.spki_pin);
    let client_tls = client_config(&client, server.spki_pin);

    let sessions = spawn_sessions(server_tls.config, 1, |_, _, _| Ok(()));
    let (_stream, conn) = connect(sessions.port, client_tls).expect("client handshake");
    sessions.finish()[0].as_ref().expect("server session");

    assert_eq!(conn.protocol_version(), Some(ProtocolVersion::TLSv1_3));
    assert_eq!(conn.alpn_protocol(), Some(ALPN));

    let suite = conn
        .negotiated_cipher_suite()
        .expect("negotiated cipher suite")
        .suite();
    assert!(
        matches!(
            suite,
            CipherSuite::TLS13_AES_256_GCM_SHA384
                | CipherSuite::TLS13_AES_128_GCM_SHA256
                | CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        ),
        "unexpected negotiated suite: {suite:?}"
    );

    let group = conn
        .negotiated_key_exchange_group()
        .expect("negotiated key exchange group");
    assert_eq!(
        group.name(),
        NamedGroup::X25519,
        "the client prefers X25519 and the server accepts it"
    );
}
