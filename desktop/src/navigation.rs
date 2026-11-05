//! Navigation allowlist for the desktop webview.
//!
//! The window may load only the embedded Tauri asset origin for its platform.
//! It cannot navigate to the asset origin of another platform, a remote host,
//! a local file, or a data URL.

/// The asset origin that the platform webview uses.
///
/// Both variants remain in the binary so the tests can check both rules on one
/// host. The platform constant selects one variant at compile time.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AssetOrigin {
    /// macOS and Linux use the custom `tauri` protocol.
    Tauri,
    /// Windows uses the `http` protocol on `tauri.localhost`.
    Http,
}

#[cfg(target_os = "windows")]
const PLATFORM_ASSET_ORIGIN: AssetOrigin = AssetOrigin::Http;

#[cfg(not(target_os = "windows"))]
const PLATFORM_ASSET_ORIGIN: AssetOrigin = AssetOrigin::Tauri;

/// True when the URL is the platform asset origin or the blank page.
pub fn allow(url: &tauri::Url) -> bool {
    allow_for_platform(url, PLATFORM_ASSET_ORIGIN)
}

/// Check one URL against one explicit asset origin.
///
/// The platform selector is a parameter so the tests can cover the Windows and
/// Unix rules on either host. The public `allow` function fixes the selector at
/// compile time.
fn allow_for_platform(url: &tauri::Url, origin: AssetOrigin) -> bool {
    if url.as_str() == "about:blank" {
        return true;
    }
    if !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    match (origin, url.scheme()) {
        (AssetOrigin::Tauri, "tauri") => {
            url.host_str() == Some("localhost") && url.port().is_none()
        }
        (AssetOrigin::Http, "http") => {
            url.host_str() == Some("tauri.localhost") && url.port().is_none()
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed(input: &str) -> bool {
        allow(&tauri::Url::parse(input).expect("test URL"))
    }

    fn allowed_on(input: &str, origin: AssetOrigin) -> bool {
        allow_for_platform(&tauri::Url::parse(input).expect("test URL"), origin)
    }

    #[test]
    fn allows_only_the_platform_asset_origin() {
        assert!(allowed("about:blank"));

        if cfg!(target_os = "windows") {
            assert!(allowed("http://tauri.localhost/index.html"));
            assert!(!allowed("tauri://localhost/index.html"));
        } else {
            assert!(allowed("tauri://localhost/index.html"));
            assert!(allowed("tauri://localhost/index.html#settings"));
            assert!(allowed("tauri://localhost/api/status"));
            assert!(!allowed("http://tauri.localhost/index.html"));
        }
    }

    #[test]
    fn the_unix_origin_rule_rejects_the_windows_origin() {
        assert!(allowed_on(
            "tauri://localhost/index.html",
            AssetOrigin::Tauri
        ));
        assert!(!allowed_on(
            "http://tauri.localhost/index.html",
            AssetOrigin::Tauri
        ));
    }

    #[test]
    fn the_windows_origin_rule_rejects_the_unix_origin() {
        assert!(allowed_on(
            "http://tauri.localhost/index.html",
            AssetOrigin::Http
        ));
        assert!(!allowed_on(
            "tauri://localhost/index.html",
            AssetOrigin::Http
        ));
    }

    #[test]
    fn rejects_every_other_origin_and_scheme() {
        for origin in [AssetOrigin::Tauri, AssetOrigin::Http] {
            assert!(!allowed_on("https://evil.example/", origin));
            assert!(!allowed_on("http://127.0.0.1:8787/", origin));
            assert!(!allowed_on("http://localhost:8787/", origin));
            assert!(!allowed_on("tauri://evil.example/index.html", origin));
            assert!(!allowed_on("tauri://localhost:1234/index.html", origin));
            assert!(!allowed_on("http://tauri.localhost.evil.example/", origin));
            assert!(!allowed_on("tauri://localhost@evil.example/", origin));
            assert!(!allowed_on("http://tauri.localhost:1234/", origin));
            assert!(!allowed_on("file:///etc/passwd", origin));
            assert!(!allowed_on("data:text/html,hello", origin));
            assert!(!allowed_on("javascript:alert(1)", origin));
        }
    }
}
