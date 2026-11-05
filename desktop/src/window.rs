//! Window setup for the desktop demo.
//!
//! The desktop binary and the webview smoke test use this builder, so both
//! load the same embedded page, install the same fetch shim, and apply the same
//! navigation rule. The test hides the window and adds one test-only script.

use tauri::webview::NewWindowResponse;
use tauri::{Manager, Runtime, WebviewUrl, WebviewWindowBuilder};

use crate::navigation;

/// Build the demo window.
///
/// The window loads the embedded `index.html` in a native decorated frame. The
/// fetch shim is an initialization script. The window stays on the asset origin
/// and cannot open a second window.
pub fn builder<'a, R: Runtime, M: Manager<R>>(manager: &'a M) -> WebviewWindowBuilder<'a, R, M> {
    WebviewWindowBuilder::new(manager, "main", WebviewUrl::App("index.html".into()))
        .title("HotspotShade Desktop (Demo)")
        .inner_size(960.0, 700.0)
        .min_inner_size(780.0, 560.0)
        .initialization_script(include_str!("fetch_shim.js"))
        .on_navigation(navigation::allow)
        // The page cannot open a second window.
        .on_new_window(|_, _| NewWindowResponse::Deny)
}
