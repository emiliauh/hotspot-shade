//! The legacy macOS administrator helper must stay unavailable.
//!
//! The app starts a root engine through the protected XPC helper. The old
//! `--privileged-helper` command accepted a user-owned socket path and ran the
//! bundled engine as root. It must fail closed instead of starting a service.
#![cfg(target_os = "macos")]

use std::process::Command;

#[test]
fn legacy_privileged_helper_command_fails_closed() {
    let output = Command::new(env!("CARGO_BIN_EXE_hotspotshade"))
        .args([
            "--privileged-helper",
            "/tmp/hotspotshade-not-a-socket",
            "501",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("legacy administrator helper is not available"),
        "{stderr}"
    );
}
