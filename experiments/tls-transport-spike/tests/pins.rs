//! Pin semantics that the transport tests depend on.

use tls_transport_spike::{certificate_spki, Pin, TestIdentity};

#[test]
fn spki_pin_survives_reissue_and_certificate_pin_does_not() {
    let original = TestIdentity::server();
    let renewed = original.reissued();

    assert_eq!(
        original.spki_pin, renewed.spki_pin,
        "a new certificate for the same key keeps the SPKI pin"
    );
    assert_ne!(
        original.cert_pin, renewed.cert_pin,
        "a whole-certificate pin changes when the certificate is reissued"
    );
    assert_ne!(
        original.cert_der, renewed.cert_der,
        "reissue must produce different DER"
    );
}

#[test]
fn certificate_parser_matches_the_generated_spki() {
    let identity = TestIdentity::server();
    let extracted = certificate_spki(&identity.cert_der).expect("SPKI");
    assert_eq!(extracted, identity.spki_der);
    assert_eq!(Pin::of_spki(&extracted), identity.spki_pin);
}

#[test]
fn malformed_certificate_has_no_spki() {
    assert!(certificate_spki(&[]).is_none());
    assert!(certificate_spki(&[0x30, 0x00]).is_none());
    assert!(certificate_spki(&[0x30, 0x82, 0xff, 0xff]).is_none());
    assert!(certificate_spki(b"not a certificate").is_none());
}

#[test]
fn malformed_lengths_and_truncated_input_do_not_panic() {
    // The previous hand-written DER walker could overflow `usize` on a 32-bit
    // target while adding a four-byte length. rustls's parser rejects these
    // inputs without arithmetic that can wrap. This test is a small
    // fuzz-like guard, not a proof of parser safety.
    let cases: &[&[u8]] = &[
        &[0x30, 0x84, 0xff, 0xff, 0xff, 0xff],
        &[0x30, 0x83, 0xff, 0xff, 0xff],
        &[0x30, 0x84, 0x00, 0x00, 0x00, 0x01, 0x30],
        &[0x30, 0x89, 0x01],
        &[0x30, 0x80],
        &[0x30, 0x81, 0x00],
        &[0xff, 0xff, 0xff, 0xff],
    ];
    for case in cases {
        assert!(
            certificate_spki(case).is_none(),
            "malformed input must produce no SPKI"
        );
    }
}

#[test]
fn pin_hex_is_a_sha256_digest() {
    let identity = TestIdentity::client();
    assert_eq!(identity.spki_pin.hex().len(), 64);
    assert_eq!(identity.cert_pin.hex().len(), 64);
    assert_eq!(
        Pin::of_spki(b"fixed public bytes"),
        Pin::of_spki(b"fixed public bytes")
    );
}
