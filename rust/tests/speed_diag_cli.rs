//! The speed diagnostic, the UDP responder, and the tunnel token input must
//! reject unsafe input before they read a secret or open a socket. These tests
//! need no phone, no root, and change no route.
#![cfg(unix)]

use std::process::{Command, Stdio};

fn run(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_hotspotshade"))
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

const BASE: [&str; 9] = [
    "phone-speed-diag",
    "--phone",
    "172.20.10.1:18080",
    "--iface",
    "en6",
    "--host",
    "speed.example.net",
    "--download-path",
    "/down",
];

#[test]
fn speed_diag_rejects_secret_arguments_without_echo() {
    let canary = "CANARY-TOKEN-5678";
    for flag in ["--token", "--udp-secret", "--secret", "--password"] {
        let mut args = BASE.to_vec();
        args.extend([flag, canary]);
        let (code, stdout, stderr) = run(&args);
        assert_eq!(code, 1);
        assert!(stderr.contains("unsupported option"), "{stderr}");
        assert!(!stdout.contains(canary) && !stderr.contains(canary));
    }
}

#[test]
fn speed_diag_rejects_unscoped_input_before_prompt() {
    for (extra, expect) in [
        (vec!["--paths", "direct"], "numeric --address"),
        (vec!["--port", "443"], "TLS"),
        (vec!["--streams", "64"], "streams"),
        (vec!["--max-mb", "99999"], "max-mb"),
        (vec!["--address", "10.1.2.3"], "public unicast"),
    ] {
        let mut args = BASE.to_vec();
        args.extend(extra);
        let (code, _, stderr) = run(&args);
        assert_eq!(code, 1);
        assert!(stderr.contains(expect), "{stderr}");
        assert!(!stderr.contains("terminal"), "{stderr}");
    }
    for iface in ["utun4", "lo0", "bridge100"] {
        let mut args = BASE.to_vec();
        args[4] = iface;
        let (code, _, stderr) = run(&args);
        assert_eq!(code, 1);
        assert!(stderr.contains("physical hotspot interface"), "{stderr}");
    }
    let mut args = BASE.to_vec();
    args[4] = "zz9";
    let (code, _, stderr) = run(&args);
    assert_eq!(code, 1);
    assert!(stderr.contains("does not exist"), "{stderr}");
    let mut args = BASE.to_vec();
    args[6] = "https://speed.example.net/";
    let (code, _, stderr) = run(&args);
    assert_eq!(code, 1);
    assert!(stderr.contains("plain HTTP"), "{stderr}");
}

#[test]
fn responder_rejects_unbounded_input() {
    for args in [
        vec!["udp-responder"],
        vec![
            "udp-responder",
            "--listen",
            "127.0.0.1:9",
            "--max-pps",
            "50000",
        ],
        vec![
            "udp-responder",
            "--listen",
            "127.0.0.1:9",
            "--seconds",
            "86400",
        ],
        vec!["udp-responder", "--listen", "localhost:9"],
    ] {
        let (code, _, _) = run(&args);
        assert_eq!(code, 1, "{args:?}");
    }
}

#[test]
fn tunnel_and_adapter_take_no_token_argument() {
    let canary = "CANARY-TOKEN-9012";
    for args in [
        vec!["tun", "--phone", "172.20.10.1:18080", "--token", canary],
        vec!["phone", "--phone", "172.20.10.1:18080", "--token", canary],
    ] {
        let (code, stdout, stderr) = run(&args);
        assert_eq!(code, 1);
        assert!(stderr.contains("unsupported option"), "{stderr}");
        assert!(!stdout.contains(canary) && !stderr.contains(canary));
    }
    let (code, _, stderr) = run(&["tun", "--secrets-fd", "0"]);
    assert_eq!(code, 1);
    assert!(stderr.contains("needs --phone"), "{stderr}");
}

#[test]
fn speed_diag_rejects_the_removed_native_udp_flags() {
    for flag in [["--udp-mode", "native"], ["--udp-port", "18081"]] {
        let mut args = BASE.to_vec();
        args.extend(flag);
        let (code, _, stderr) = run(&args);
        assert_eq!(code, 1);
        assert!(stderr.contains("unsupported option"), "{stderr}");
    }
}
