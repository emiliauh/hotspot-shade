//! The scoped UDP diagnostic must reject unsafe input before it reads a
//! secret or opens a socket. These tests need no phone and change no route.
#![cfg(unix)]

use std::process::{Command, Stdio};

fn run(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_hotspotshade"))
        .arg("phone-udp-diag")
        .args(args)
        .env_remove("HOTSPOTSHADE_PHONE_TOKEN")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

const BASE: [&str; 4] = [
    "--phone",
    "172.20.10.1:18080",
    "--target",
    "74.125.250.129:19302",
];

#[test]
fn rejects_secret_arguments_without_echo() {
    let canary = "CANARY-TOKEN-1234";
    for flag in ["--token", "--secret"] {
        let mut args = BASE.to_vec();
        args.extend(["--iface", "en6", flag, canary]);
        let (code, stdout, stderr) = run(&args);
        assert_eq!(code, 1);
        assert!(stderr.contains("unsupported option"));
        assert!(!stdout.contains(canary) && !stderr.contains(canary));
    }
}

#[test]
fn rejects_tunnel_loopback_and_missing_interfaces_before_prompt() {
    for iface in ["utun3", "lo0", "bridge100"] {
        let mut args = BASE.to_vec();
        args.extend(["--iface", iface]);
        let (code, _, stderr) = run(&args);
        assert_eq!(code, 1);
        assert!(stderr.contains("physical hotspot interface"), "{stderr}");
    }
    let mut args = BASE.to_vec();
    args.extend(["--iface", "zz9"]);
    let (code, _, stderr) = run(&args);
    assert_eq!(code, 1);
    assert!(stderr.contains("does not exist"), "{stderr}");
    assert!(!stderr.contains("terminal"), "{stderr}");
}

#[test]
fn rejects_hostname_target_and_native_flags() {
    let (code, _, stderr) = run(&[
        "--phone",
        "172.20.10.1:18080",
        "--iface",
        "en6",
        "--target",
        "stun.example.test:19302",
    ]);
    assert_eq!(code, 1);
    assert!(stderr.contains("numeric"), "{stderr}");
    // The removed native UDP flags are unsupported options now.
    for flag in [
        ["--modes", "native"],
        ["--udp-port", "18081"],
        ["--udp-secret", "x"],
    ] {
        let mut args = BASE.to_vec();
        args.extend(["--iface", "en6"]);
        args.extend(flag);
        let (code, _, stderr) = run(&args);
        assert_eq!(code, 1);
        assert!(stderr.contains("unsupported option"), "{stderr}");
    }
}
