//! Hermetic checks for the committed desktop UI assets.
//!
//! The desktop demo has its own page under `ui/`. It does not copy the local
//! web GUI at build time. These tests catch an external asset, a route outside
//! the demo bridge, a weakened Content Security Policy, or a missing demo
//! label.

use std::fs;
use std::path::Path;

use hotspotshade_desktop::bridge::ALLOWED_PATHS;

const UI_FILES: &[&str] = &[
    "index.html",
    "styles.css",
    "app.js",
    "model.js",
    "boot.js",
    "favicon.svg",
];

fn read_ui(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("ui").join(name);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn api_paths(source: &str) -> Vec<String> {
    let mut paths = Vec::new();
    for (start, _) in source.match_indices("/api/") {
        let rest = &source[start..];
        let end = rest
            .find(|character: char| {
                !(character.is_ascii_alphanumeric() || matches!(character, '/' | '_' | '-' | '?'))
            })
            .unwrap_or(rest.len());
        let token = &rest[..end];
        let path = token.split('?').next().unwrap_or(token);
        paths.push(path.to_string());
    }
    paths
}

#[test]
fn every_ui_file_exists() {
    for name in UI_FILES {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("ui").join(name);
        let metadata = fs::metadata(&path).unwrap_or_else(|error| {
            panic!("missing {}: {error}", path.display());
        });
        assert!(metadata.len() > 0, "{} is empty", path.display());
    }
}

#[test]
fn the_page_uses_only_local_assets() {
    let html = read_ui("index.html");
    for marker in ["src=\"", "href=\""] {
        for part in html.split(marker).skip(1) {
            let end = part.find('"').unwrap_or(0);
            let value = &part[..end];
            assert!(
                !value.starts_with("http://") && !value.starts_with("https://"),
                "external asset: {value}"
            );
        }
    }
    let css = read_ui("styles.css");
    assert!(!css.contains("@import"), "external CSS import");
    for marker in ["url(http://", "url(https://"] {
        assert!(!css.contains(marker), "external CSS URL: {marker}");
    }
    for (name, source) in [
        ("app.js", read_ui("app.js")),
        ("model.js", read_ui("model.js")),
    ] {
        for marker in [
            "fetch('http://",
            "fetch(\"http://",
            "fetch('https://",
            "fetch(\"https://",
        ] {
            assert!(
                !source.contains(marker),
                "{name} has a remote fetch: {marker}"
            );
        }
    }
}

#[test]
fn the_page_names_only_bridge_paths() {
    let mut seen = Vec::new();
    for name in ["app.js", "model.js", "boot.js"] {
        for path in api_paths(&read_ui(name)) {
            assert!(
                ALLOWED_PATHS.contains(&path.as_str()),
                "{name} names a path outside the bridge: {path}"
            );
            if !seen.contains(&path) {
                seen.push(path);
            }
        }
    }
    for path in ["/api/status", "/api/start", "/api/stop", "/api/phone/pair"] {
        assert!(
            seen.contains(&path.to_string()),
            "the page never calls {path}"
        );
    }
}

#[test]
fn the_demo_label_is_visible_and_explained() {
    let html = read_ui("index.html");
    assert!(html.contains("id=\"demoPill\""));
    assert!(html.contains("id=\"demoBanner\""));
    assert!(html.contains("All data is simulated. No tunnel, routes, or network traffic."));
    assert!(html.contains("No Windows or Linux tunnel support."));
    assert!(html.contains("id=\"view-dashboard\""));
    assert!(html.contains("id=\"view-activity\""));
    assert!(html.contains("id=\"view-settings\""));
}

#[test]
fn both_themes_have_tokens() {
    let css = read_ui("styles.css");
    assert!(css.contains(":root {"));
    assert!(css.contains("[data-theme=\"dark\"]"));
    for token in [
        "--bg:",
        "--fg:",
        "--card:",
        "--muted-fg:",
        "--border:",
        "--primary:",
        "--ring:",
        "--success:",
        "--warning:",
        "--danger:",
        "--radius:",
    ] {
        assert!(css.contains(token), "missing token {token}");
    }
    assert!(read_ui("boot.js").contains("prefers-color-scheme: dark"));
}

#[test]
fn the_content_security_policy_is_not_weakened() {
    let config = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tauri.conf.json"))
        .expect("read tauri.conf.json");
    let value: serde_json::Value = serde_json::from_str(&config).expect("parse tauri.conf.json");
    let csp = value["app"]["security"]["csp"]
        .as_str()
        .expect("CSP string");
    assert_eq!(
        csp,
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self' ipc: http://ipc.localhost; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    );
    assert!(!csp.contains("unsafe-eval"));
    assert!(!csp.contains("http://*"));
    assert!(!csp.contains("https://*"));
}
