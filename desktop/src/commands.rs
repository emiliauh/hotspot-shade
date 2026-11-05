//! The one command that the demo page can call.
//!
//! The arguments are a method, a path, a query, and a JSON body. A body can
//! contain a manual token, host, or port. The demo does not contact a device.
//! The bridge checks every method and path against a fixed allowlist.

use crate::bridge::{ApiReply, DemoBridge};

/// Handle one page request with the in-memory demo backend.
#[tauri::command]
pub fn demo_api(
    state: tauri::State<'_, DemoBridge>,
    method: String,
    path: String,
    query: Option<String>,
    body: Option<serde_json::Value>,
) -> ApiReply {
    state.handle(&method, &path, query.as_deref().unwrap_or(""), body)
}

/// Build the invoke handler for the demo command.
///
/// The desktop binary and the webview smoke test register the same handler, so
/// the test exercises the real command and the real allowlist.
pub fn handler<R: tauri::Runtime>() -> impl Fn(tauri::ipc::Invoke<R>) -> bool + Send + Sync + 'static
{
    tauri::generate_handler![demo_api]
}
