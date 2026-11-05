//! Cross-implementation pairing interop test against the Android source app.
//!
//! The test needs a booted Android emulator, the instrumented
//! `PairingInteropTest`, an `adb forward` from this host, and the
//! `HS_PAIRING_PORT` environment variable. It is ignored by default.
//!
//! The test uses the real target `pair_at` client. The pairing sockets use the
//! normalized helpers with TTL 65 and no interface pinning. The test sets no
//! route, creates no tunnel device, and uses no carrier, real phone, or DNS
//! lookup. An emulator loopback does not prove hotspot, carrier, or physical
//! device behavior.
#![cfg(any(unix, windows))]

use hotspotshade::{
    normalization::Audit,
    pairing::{pair_at, Identity, PairTimeouts},
};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::AtomicBool;

const TOKEN: &str = "emulator-pairing-token";
const PROXY_PORT: u16 = 1080;

fn pairing_port() -> Option<u16> {
    let value = std::env::var("HS_PAIRING_PORT").ok()?;
    match value.parse() {
        Ok(port) => Some(port),
        Err(_) => panic!("HS_PAIRING_PORT is not a TCP port: {value}"),
    }
}

fn assert_code_format(code: &str) {
    let parts: Vec<&str> = code.split(' ').collect();
    assert_eq!(parts.len(), 2, "the code is two groups of three digits");
    assert_eq!(parts[0].len(), 3, "the first group has three digits");
    assert_eq!(parts[1].len(), 3, "the second group has three digits");
    assert!(
        parts
            .iter()
            .all(|part| part.bytes().all(|byte| byte.is_ascii_digit())),
        "the code holds decimal digits only"
    );
}

#[test]
#[ignore = "needs a booted Android emulator and HS_PAIRING_PORT"]
fn android_source_pairing_interop() {
    let Some(port) = pairing_port() else {
        eprintln!("HS_PAIRING_PORT is not set, so the Android pairing test is skipped.");
        return;
    };
    let identity = Identity::from_bytes([0x11; 32]);
    let audit = Audit::default();
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));

    // (a) The first pairing is unknown. The app shows a prompt, the
    // instrumented test approves it, and the client receives credentials.
    let mut first_code = String::new();
    let first = pair_at(
        address,
        &identity,
        None,
        &audit,
        &AtomicBool::new(false),
        PairTimeouts::default(),
        |code| first_code = code.to_string(),
    )
    .expect("the Android source device must complete the first pairing");
    assert_code_format(&first_code);
    assert_eq!(first.host, Ipv4Addr::LOCALHOST);
    assert_eq!(first.port, PROXY_PORT);
    assert_eq!(first.token, TOKEN);
    assert!(
        !first_code.is_empty(),
        "the target device must learn the displayed code"
    );

    // (b) The second pairing uses the trusted key. The app sends credentials
    // without a prompt, and the target client still computes the code.
    let mut second_code = String::new();
    let second = pair_at(
        address,
        &identity,
        None,
        &audit,
        &AtomicBool::new(false),
        PairTimeouts::default(),
        |code| second_code = code.to_string(),
    )
    .expect("the Android source device must accept the known target device");
    assert_code_format(&second_code);
    assert_eq!(second.host, Ipv4Addr::LOCALHOST);
    assert_eq!(second.port, PROXY_PORT);
    assert_eq!(second.token, TOKEN);

    // (c) Both pairings used a normalized outer socket with TTL 65.
    let (outer_sockets, ttl_bad) = audit.snapshot();
    assert_eq!(outer_sockets, 2, "one outer socket for each pairing");
    assert_eq!(ttl_bad, 0, "every outer socket must keep TTL 65");
}
