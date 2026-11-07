//! Cross-implementation pairing interop tests against the Android source app.
//!
//! The tests need a booted Android emulator, the matching instrumented fixture,
//! an `adb forward` from this host, and the `HS_PAIRING_PORT` environment
//! variable. They are ignored by default. Running one explicitly without a
//! valid nonzero port fails.
//!
//! `android_source_pairing_interop` serves `PairingInteropTest`. The lifecycle
//! test, `android_source_pairing_lifecycle_interop`, serves
//! `PairingLifecycleInteropTest` and requires `HS_PAIRING_PORT=18090`. The
//! public `status` and `forget_attempt` clients use the fixed pairing port
//! 18090, so one host forward from 18090 must reach the fixture listener.
//!
//! The tests use the real target `pair_at`, `status`, and `forget_attempt`
//! clients. The pairing sockets use the normalized helpers with TTL 65 and no
//! interface pinning. The tests set no route, create no tunnel device, and use
//! no carrier, real phone, or DNS lookup. An emulator loopback does not prove
//! hotspot, carrier, or physical device behavior.
#![cfg(any(unix, windows))]

use hotspotshade::{
    normalization::Audit,
    pairing::{
        forget_attempt, pair_at, status, ForgetReply, Identity, PairError, PairTimeouts,
        PhoneStatus, PAIRING_PORT,
    },
};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::AtomicBool;

const TOKEN: &str = "emulator-pairing-token";
const PROXY_PORT: u16 = 1080;
const KNOWN_IDENTITY: [u8; 32] = [0x11; 32];
const UNKNOWN_IDENTITY: [u8; 32] = [0x22; 32];

fn pairing_port() -> u16 {
    let value = std::env::var("HS_PAIRING_PORT")
        .expect("set HS_PAIRING_PORT to the emulator pairing forward port");
    let port: u16 = value.parse().expect("HS_PAIRING_PORT must be a TCP port");
    assert_ne!(port, 0, "HS_PAIRING_PORT must be nonzero");
    port
}

fn fixed_pairing_port() -> u16 {
    let port = pairing_port();
    assert_eq!(
        port, PAIRING_PORT,
        "the lifecycle test needs host port 18090 because status and forget use \
         the fixed pairing port; forward host 18090 to the fixture listener"
    );
    port
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
    let port = pairing_port();
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

/// Exercise the pairing lifecycle against the real Android responder.
///
/// The fixture approves its first, unknown-target prompt and denies every
/// later prompt. A known-key second pairing that prompted again would
/// therefore fail with `Phone(Denied)`. The second pairing must succeed and
/// the fixture asserts `prompts == 1` exactly at the end of the run. The
/// fixture also serves one authenticated status answer for the trusted key,
/// rejects status for an unknown key, applies the remote FORGET, and then
/// reports the forgotten key as unknown.
#[test]
#[ignore = "needs a booted Android emulator, PairingLifecycleInteropTest, and host port 18090"]
fn android_source_pairing_lifecycle_interop() {
    let port = fixed_pairing_port();
    let identity = Identity::from_bytes(KNOWN_IDENTITY);
    let unknown = Identity::from_bytes(UNKNOWN_IDENTITY);
    let audit = Audit::default();
    let cancel = AtomicBool::new(false);
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));

    // (a) The first pairing is unknown. The fixture prompts once and approves
    // that prompt, and the target device receives the fixed test token.
    let mut first_code = String::new();
    let first = pair_at(
        address,
        &identity,
        None,
        &audit,
        &cancel,
        PairTimeouts::default(),
        |code| first_code = code.to_string(),
    )
    .expect("the Android source device must complete the first pairing");
    assert_code_format(&first_code);
    assert_eq!(first.host, Ipv4Addr::LOCALHOST);
    assert_eq!(first.port, PROXY_PORT);
    assert_eq!(first.token, TOKEN);

    // (b) The second pairing claims a trusted key. The fixture denies any
    // prompt after the first, so this success is the host-side exact
    // one-prompt check. The fixture asserts the exact prompt count too.
    let mut second_code = String::new();
    let second = pair_at(
        address,
        &identity,
        None,
        &audit,
        &cancel,
        PairTimeouts::default(),
        |code| second_code = code.to_string(),
    )
    .expect("the trusted key must pair without a second prompt");
    assert_code_format(&second_code);
    assert_eq!(second.host, Ipv4Addr::LOCALHOST);
    assert_eq!(second.port, PROXY_PORT);
    assert_eq!(second.token, TOKEN);

    // (c) The trusted key gets one authenticated status answer. The fixture
    // reports no live proxy, its fixed proxy port, and the loopback host that
    // the target device connected to.
    let info = status(Ipv4Addr::LOCALHOST, &identity, None, &audit, &cancel)
        .expect("the trusted target device must receive status");
    assert_eq!(info.host, Ipv4Addr::LOCALHOST.to_string());
    assert_eq!(info.port, PROXY_PORT);
    assert!(!info.proxy_running, "the fixture serves no source proxy");
    assert!(info.foreground, "the fixture reports the app as visible");
    assert_eq!(info.connections, 0, "the fixture has no proxy sessions");

    // (d) An unknown key gets no status. The source device rejects the
    // request before it creates a prompt, so this does not consume the one
    // approved prompt.
    let error = status(Ipv4Addr::LOCALHOST, &unknown, None, &audit, &cancel)
        .expect_err("an unknown target device must not receive status");
    assert_eq!(error, PairError::Phone(PhoneStatus::Rejected));
    assert!(
        !error.to_string().contains(TOKEN),
        "the status error must not contain the source device token"
    );

    // (e) Send one remote FORGET for the trusted key. Protocol v1 answers with
    // a plaintext RESULT, so `Acknowledged` is only the peer's claim. The
    // fixture uses an in-memory trust store that removes the key for this run,
    // but this result does not prove durable remote revocation, and a peer on
    // the path can send the same bytes. Do not report confirmed deletion.
    let reply = forget_attempt(Ipv4Addr::LOCALHOST, &identity, None, &audit, &cancel)
        .expect("the source device must answer the FORGET");
    assert_eq!(
        reply,
        ForgetReply::Acknowledged,
        "the fixture must acknowledge the FORGET after it removes the key"
    );

    // (f) The forgotten key gets no status. This is the follow-up untrusted
    // status check for the same real source device that held the key.
    let error = status(Ipv4Addr::LOCALHOST, &identity, None, &audit, &cancel)
        .expect_err("the forgotten target device must not receive status");
    assert_eq!(error, PairError::Phone(PhoneStatus::Rejected));
    assert!(
        !error.to_string().contains(TOKEN),
        "the status error must not contain the source device token"
    );

    // (g) Two pairings, one trusted status, one unknown status, one FORGET,
    // and one post-FORGET status each used one normalized outer socket.
    let (outer_sockets, ttl_bad) = audit.snapshot();
    assert_eq!(
        outer_sockets, 6,
        "one outer socket for each pairing and authenticated command"
    );
    assert_eq!(ttl_bad, 0, "every outer socket must keep TTL 65");
}
