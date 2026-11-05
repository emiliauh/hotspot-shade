//! The Windows build must report real errors for the commands that it does
//! not implement. It must not panic and must not create a tunnel device or a
//! route.
#![cfg(windows)]

use std::process::Command;

#[test]
fn unsupported_commands_report_a_clear_error() {
    for command in [
        "--privileged-helper",
        "socks5",
        "phone",
        "phone-udp-diag",
        "phone-speed-diag",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_hotspotshade"))
            .arg(command)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{command}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("The tunnel is not implemented on Windows."),
            "{command}: {stderr}"
        );
    }
}

#[test]
fn probe_reports_read_only_values_without_a_tunnel() {
    let output = Command::new(env!("CARGO_BIN_EXE_hotspotshade"))
        .arg("probe")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("UDP TTL: 65"), "{stdout}");
    assert!(stdout.contains("TTL audit failures: 0"), "{stdout}");
}

#[test]
fn a_tunnel_start_without_a_source_device_names_the_mode_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_hotspotshade"))
        .arg("tun")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("source device proxy mode requires --phone"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("The tunnel is not implemented on Windows."),
        "{stderr}"
    );
}

#[test]
fn a_tunnel_start_with_a_missing_wintun_path_names_the_dependency() {
    let output = Command::new(env!("CARGO_BIN_EXE_hotspotshade"))
        .args([
            "tun",
            "--phone",
            "172.20.10.1:1234",
            "--iface",
            "1",
            "--wintun",
            r"C:\hotspotshade-test\missing\wintun.dll",
        ])
        .env("HOTSPOTSHADE_PHONE_TOKEN", "test-only")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    // The process checks Administrator rights before it loads the DLL.
    assert!(
        stderr.contains("administrator privileges") || stderr.contains("wintun.dll"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("The tunnel is not implemented on Windows."),
        "{stderr}"
    );
}
