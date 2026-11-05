//! Bounded hermetic smoke test for the desktop webview.
//!
//! This test creates one visible Tauri window. The window loads the embedded
//! `index.html` through the production window builder, installs the production
//! fetch shim, and registers the production `demo_api` command. A test-only
//! script waits for the page to render the demo label, checks the asset origin,
//! the shim, and the demo status, and sends one report to this binary.
//!
//! The test opens no listener and makes no external request. It does not start
//! the demo backend's tunnel and does not change a route or a device.
//!
//! Run it with:
//! `cargo test --locked --manifest-path desktop/Cargo.toml --features webview-smoke --test webview_smoke`
//!
//! The target needs a graphical session and a system webview. On a host without
//! either one, the test fails with a timeout or a start error. It never reports
//! a pass without a report from the webview.
//!
//! A pass verifies the measured window layouts and theme change as well as the
//! embedded page, shim, and demo status. It does not prove a real service, a
//! tunnel, or live platform support.

use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

use hotspotshade_desktop::bridge::DemoBridge;
use hotspotshade_desktop::commands;
use hotspotshade_desktop::menu;
use hotspotshade_desktop::window;

/// The time limit for the complete test, in seconds.
const TIMEOUT: Duration = Duration::from_secs(90);

/// The test-only page script. It runs after the production fetch shim.
const SMOKE_SCRIPT: &str = include_str!("webview_smoke.js");

/// The final result. A value of -1 means the webview closed without a report.
static RESULT: AtomicI32 = AtomicI32::new(-1);

/// Receive the one report from the page and stop the event loop.
///
/// This command exists only in this test binary. The desktop binary registers
/// `demo_api` alone.
/// Resize the hidden test window. This command exists only in this test binary.
#[tauri::command]
fn smoke_resize(window: tauri::WebviewWindow, width: f64, height: f64) -> Result<(), String> {
    window
        .set_size(tauri::LogicalSize::new(width, height))
        .map_err(|error| error.to_string())
}

/// Run one fixed native menu action. This command exists only in this test
/// binary. The production menu uses the same handler.
#[tauri::command]
fn smoke_menu(app: tauri::AppHandle, id: String) {
    menu::handle(&app, &id);
}

#[tauri::command]
fn smoke_report(app: tauri::AppHandle, payload: serde_json::Value) {
    if payload.get("partial").and_then(serde_json::Value::as_bool) == Some(true) {
        let text = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string());
        println!("WEBVIEW SMOKE PROGRESS {text}");
        return;
    }
    let pass = payload
        .get("pass")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let text = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string());
    println!("WEBVIEW SMOKE RESULT {text}");
    if pass {
        println!("WEBVIEW SMOKE PASS");
    } else {
        eprintln!("WEBVIEW SMOKE FAIL");
    }
    RESULT.store(if pass { 0 } else { 1 }, Ordering::SeqCst);
    app.exit(if pass { 0 } else { 1 });
}

fn main() {
    if !cfg!(target_os = "macos") {
        eprintln!("WEBVIEW SMOKE FAIL: this test is implemented for macOS only.");
        std::process::exit(3);
    }

    eprintln!(
        "WEBVIEW SMOKE: opening a visible webview. The test has a {} s limit.",
        TIMEOUT.as_secs()
    );

    // The event loop can wait without a limit. The watchdog makes the test
    // bounded and gives a clear failure when the webview does not report.
    std::thread::spawn(|| {
        std::thread::sleep(TIMEOUT);
        if RESULT.load(Ordering::SeqCst) == -1 {
            eprintln!(
                "WEBVIEW SMOKE FAIL: no report after {} s. Check that this host has a graphical session and a system webview.",
                TIMEOUT.as_secs()
            );
        } else {
            eprintln!("WEBVIEW SMOKE FAIL: the webview reported a result but did not exit.");
        }
        std::process::exit(2);
    });

    let demo = commands::handler::<tauri::Wry>();
    let report: Box<dyn Fn(tauri::ipc::Invoke<tauri::Wry>) -> bool + Send + Sync> =
        Box::new(tauri::generate_handler![smoke_report]);
    let resize: Box<dyn Fn(tauri::ipc::Invoke<tauri::Wry>) -> bool + Send + Sync> =
        Box::new(tauri::generate_handler![smoke_resize]);
    let menu_action: Box<dyn Fn(tauri::ipc::Invoke<tauri::Wry>) -> bool + Send + Sync> =
        Box::new(tauri::generate_handler![smoke_menu]);

    let result = tauri::Builder::default()
        .manage(DemoBridge::new())
        .invoke_handler(move |invoke| {
            if invoke.message.command() == "smoke_report" {
                report(invoke)
            } else if invoke.message.command() == "smoke_resize" {
                resize(invoke)
            } else if invoke.message.command() == "smoke_menu" {
                menu_action(invoke)
            } else {
                demo(invoke)
            }
        })
        .setup(|app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            // Build the production menu once. This catches a runtime menu
            // error on the host. The test does not open it.
            app.set_menu(menu::build(app)?)?;

            // Show the window to exercise the production rendering path.
            // Some hidden macOS webviews update custom properties but keep
            // stale rendered styles; the assertions still check both.
            window::builder(app)
                .visible(true)
                // Keep the bounded test sequence responsive if the window is
                // temporarily obscured on a shared graphical session.
                .background_throttling(tauri::utils::config::BackgroundThrottlingPolicy::Disabled)
                .initialization_script(SMOKE_SCRIPT)
                .build()?;
            Ok(())
        })
        .run(tauri::generate_context!());

    match (result, RESULT.load(Ordering::SeqCst)) {
        (_, 0) => (),
        (_, 1) => std::process::exit(1),
        (Err(error), _) => {
            eprintln!("WEBVIEW SMOKE FAIL: the webview did not start: {error}");
            std::process::exit(1);
        }
        (Ok(()), _) => {
            eprintln!("WEBVIEW SMOKE FAIL: the webview closed before it sent a result.");
            std::process::exit(2);
        }
    }
}
