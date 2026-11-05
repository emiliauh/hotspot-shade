//! Manual interop test: the Rust pairing client against the iOS source app
//! running in the iOS Simulator on a mimicked hotspot interface.
//!
//! It needs HS_IOS_SIM=1, a simulator that listens on 172.20.10.1:18090, and
//! a person or script that taps Allow on the simulator prompt. It is ignored
//! in normal runs. It uses a fixed public test key and never prints the token.

use hotspotshade::{
    normalization::Audit,
    pairing::{pair_at, Identity, PairTimeouts},
    phone::PhoneProxy,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

#[test]
#[ignore = "needs the iOS Simulator and a mimicked hotspot interface"]
fn pair_with_the_ios_simulator_and_authenticate_to_its_proxy() {
    if std::env::var("HS_IOS_SIM").ok().as_deref() != Some("1") {
        eprintln!("HS_IOS_SIM is not 1; skipping");
        return;
    }
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 20, 10, 1)), 18090);
    let identity = Identity::from_bytes([0x42; 32]);
    let audit = Audit::default();
    let cancel = AtomicBool::new(false);
    let timeouts = PairTimeouts {
        connect: Duration::from_secs(5),
        challenge: Duration::from_secs(10),
        result: Duration::from_secs(120),
    };
    let credentials = pair_at(
        address,
        &identity,
        None,
        &audit,
        &cancel,
        timeouts,
        |code| {
            eprintln!("PAIRING_CODE {code}");
        },
    )
    .expect("pairing with the simulator");
    eprintln!(
        "PAIRED host={} port={} token_len={}",
        credentials.host,
        credentials.port,
        credentials.token.len()
    );
    assert_eq!(credentials.host, Ipv4Addr::new(172, 20, 10, 1));

    let proxy = PhoneProxy {
        address: SocketAddr::new(IpAddr::V4(credentials.host), credentials.port),
        username: "hotspotshade".into(),
        token: credentials.token.clone(),
        iface: None,
        timeout: Duration::from_secs(10),
    };
    let cancelled = AtomicBool::new(false);
    proxy
        .check_cancellable(&audit, &cancelled)
        .expect("authentication to the iOS source proxy");
    eprintln!("PROXY_AUTH_OK audit={:?}", audit.snapshot());
}
