//! Hermetic loopback tests for the public pairing client.
//!
//! This target runs on macOS, Linux, and Windows. It uses the portable pairing
//! module and the normalized socket helpers on each platform. It opens no
//! route, TUN device, or external socket, and it runs no DNS lookup.
//!
//! The source device proxy target (`phone_mock_source_device`) is Unix only
//! because `hotspotshade::phone` is gated `cfg(unix)`. See that file for the
//! integration handoff.

mod support;

use hotspotshade::{
    normalization::Audit,
    pairing::{pair_at, Identity, PairError, PairTimeouts, PhoneStatus},
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use support::pairing::{MockPairingSource, PairingConfig, PairingEvent, PairingFault};
use support::{TEST_HOST, TEST_PHONE_PORT, TEST_TOKEN};

fn identity() -> Identity {
    Identity::from_bytes([0x11; 32])
}

fn timeouts() -> PairTimeouts {
    PairTimeouts {
        connect: Duration::from_secs(2),
        challenge: Duration::from_secs(2),
        result: Duration::from_secs(2),
    }
}

#[test]
fn pairing_completes_on_loopback_and_both_sides_agree_on_the_code() {
    let mut mock = MockPairingSource::start(PairingConfig::default()).unwrap();
    let address = mock.address();
    let audit = Audit::default();
    let cancel = AtomicBool::new(false);
    let mut codes = Vec::new();
    let credentials = pair_at(
        address,
        &identity(),
        None,
        &audit,
        &cancel,
        timeouts(),
        |code| codes.push(code.to_owned()),
    )
    .unwrap();

    assert_eq!(codes.len(), 1);
    assert_eq!(credentials.host, TEST_HOST);
    assert_eq!(credentials.port, TEST_PHONE_PORT);
    assert_eq!(credentials.token, TEST_TOKEN);

    let report = mock.stop();
    report.assert_clean();
    assert_eq!(report.connections, 1);
    assert_eq!(report.observations[0].connection, 0);
    assert!(report.observations[0].hello_received);
    assert_eq!(
        report.observations[0].hello_flags, None,
        "a full pairing sends no status-only flag"
    );
    assert!(report.observations[0].proof_ok);
    assert_eq!(
        report.observations[0].code.as_deref(),
        Some(codes[0].as_str()),
        "the source device and the target device show one code"
    );
    assert_eq!(audit.snapshot(), (1, 0));
    assert!(
        std::net::TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_err(),
        "the mock listener must be closed after stop"
    );
}

#[test]
fn pairing_reports_source_statuses_without_credentials() {
    for status in [
        PhoneStatus::Denied,
        PhoneStatus::Busy,
        PhoneStatus::Rejected,
        PhoneStatus::TimedOut,
        PhoneStatus::NotActive,
        PhoneStatus::LockedOut,
    ] {
        let mut mock = MockPairingSource::start(PairingConfig {
            fault: PairingFault::StatusBeforeChallenge(status),
            ..Default::default()
        })
        .unwrap();
        let audit = Audit::default();
        let error = pair_at(
            mock.address(),
            &identity(),
            None,
            &audit,
            &AtomicBool::new(false),
            timeouts(),
            |_| {},
        )
        .unwrap_err();
        assert_eq!(error, PairError::Phone(status), "{status:?}");
        assert!(!error.to_string().contains(TEST_TOKEN));
        let report = mock.stop();
        report.assert_clean();
        assert_eq!(audit.snapshot(), (1, 0));
    }
}

#[test]
fn pairing_cancels_promptly_before_the_challenge() {
    let mut mock = MockPairingSource::start(PairingConfig {
        fault: PairingFault::SilentAfterHello,
        ..Default::default()
    })
    .unwrap();
    let address = mock.address();
    let audit = Arc::new(Audit::default());
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_audit = Arc::clone(&audit);
    let worker_cancel = Arc::clone(&cancel);
    let worker = thread::spawn(move || {
        pair_at(
            address,
            &identity(),
            None,
            &worker_audit,
            &worker_cancel,
            timeouts(),
            |_| {},
        )
    });

    assert!(
        mock.wait_for(PairingEvent::Hello, Duration::from_secs(2)),
        "the mock did not see the hello"
    );
    let started = Instant::now();
    cancel.store(true, Ordering::Release);
    assert_eq!(worker.join().unwrap().unwrap_err(), PairError::Cancelled);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "cancellation was not prompt"
    );
    assert_eq!(audit.snapshot(), (1, 0));
    mock.stop().assert_clean();
}

#[test]
fn pairing_cancels_promptly_while_waiting_for_the_result() {
    let mut mock = MockPairingSource::start(PairingConfig {
        fault: PairingFault::SilentAfterReveal,
        ..Default::default()
    })
    .unwrap();
    let address = mock.address();
    let audit = Arc::new(Audit::default());
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_audit = Arc::clone(&audit);
    let worker_cancel = Arc::clone(&cancel);
    let worker = thread::spawn(move || {
        pair_at(
            address,
            &identity(),
            None,
            &worker_audit,
            &worker_cancel,
            timeouts(),
            |_| {},
        )
    });

    assert!(
        mock.wait_for(PairingEvent::RevealRead, Duration::from_secs(2)),
        "the mock did not see the reveal"
    );
    let started = Instant::now();
    cancel.store(true, Ordering::Release);
    assert_eq!(worker.join().unwrap().unwrap_err(), PairError::Cancelled);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "cancellation was not prompt"
    );
    assert_eq!(audit.snapshot(), (1, 0));
    let report = mock.stop();
    report.assert_clean();
    assert!(report.observations[0].proof_ok);
    assert!(report.observations[0].code.is_some());
}

#[test]
fn pairing_deadlines_bound_a_silent_source() {
    let short = PairTimeouts {
        connect: Duration::from_secs(1),
        challenge: Duration::from_millis(150),
        result: Duration::from_millis(150),
    };
    let audit = Audit::default();

    let mut mock = MockPairingSource::start(PairingConfig {
        fault: PairingFault::SilentAfterHello,
        ..Default::default()
    })
    .unwrap();
    let started = Instant::now();
    assert_eq!(
        pair_at(
            mock.address(),
            &identity(),
            None,
            &audit,
            &AtomicBool::new(false),
            short,
            |_| {},
        )
        .unwrap_err(),
        PairError::TimedOut
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    mock.stop().assert_clean();

    let mut mock = MockPairingSource::start(PairingConfig {
        fault: PairingFault::SilentAfterReveal,
        ..Default::default()
    })
    .unwrap();
    let started = Instant::now();
    assert_eq!(
        pair_at(
            mock.address(),
            &identity(),
            None,
            &audit,
            &AtomicBool::new(false),
            short,
            |_| {},
        )
        .unwrap_err(),
        PairError::TimedOut
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    let report = mock.stop();
    report.assert_clean();
    assert!(report.observations[0].proof_ok);
    assert_eq!(audit.snapshot(), (2, 0));
}

#[test]
fn pairing_rejects_malformed_and_truncated_frames() {
    let cases = [
        (PairingFault::PartialFrame, PairError::Io),
        (PairingFault::OversizeFrame, PairError::Protocol),
        (PairingFault::CloseAfterHello, PairError::Io),
        (PairingFault::ShortChallenge, PairError::Protocol),
        (PairingFault::PartialResult, PairError::Io),
        (PairingFault::CloseAfterReveal, PairError::Io),
    ];
    for (fault, expected) in cases {
        let mut mock = MockPairingSource::start(PairingConfig {
            fault,
            ..Default::default()
        })
        .unwrap();
        let audit = Audit::default();
        let error = pair_at(
            mock.address(),
            &identity(),
            None,
            &audit,
            &AtomicBool::new(false),
            timeouts(),
            |_| {},
        )
        .unwrap_err();
        assert_eq!(error, expected, "{fault:?}");
        let report = mock.stop();
        report.assert_clean();
        assert_eq!(audit.snapshot(), (1, 0), "{fault:?}");
    }
}

#[test]
fn pairing_rejects_tampered_results_and_a_different_host() {
    let cases = [
        (PairingFault::TamperedResult, PairError::Decrypt),
        (PairingFault::WrongHost, PairError::Protocol),
    ];
    for (fault, expected) in cases {
        let mut mock = MockPairingSource::start(PairingConfig {
            fault,
            ..Default::default()
        })
        .unwrap();
        let audit = Audit::default();
        let error = pair_at(
            mock.address(),
            &identity(),
            None,
            &audit,
            &AtomicBool::new(false),
            timeouts(),
            |_| {},
        )
        .unwrap_err();
        assert_eq!(error, expected, "{fault:?}");
        assert!(!error.to_string().contains(TEST_TOKEN));
        assert!(!format!("{error:?}").contains(TEST_TOKEN));
        let report = mock.stop();
        report.assert_clean();
        assert!(report.observations[0].proof_ok);
        assert_eq!(audit.snapshot(), (1, 0));
    }
}

#[test]
fn pairing_handles_a_source_rejection_after_the_reveal() {
    let mut mock = MockPairingSource::start(PairingConfig {
        fault: PairingFault::RejectProof,
        ..Default::default()
    })
    .unwrap();
    let audit = Audit::default();
    let error = pair_at(
        mock.address(),
        &identity(),
        None,
        &audit,
        &AtomicBool::new(false),
        timeouts(),
        |_| {},
    )
    .unwrap_err();
    assert_eq!(error, PairError::Phone(PhoneStatus::Rejected));
    assert_eq!(audit.snapshot(), (1, 0));
    let report = mock.stop();
    report.assert_clean();
    assert!(
        report.observations[0].proof_ok,
        "the client sent a valid proof before the rejection"
    );
}
