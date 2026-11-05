#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! HotspotShade desktop demo.
//!
//! The shell is a labeled demo only. It has no tunnel, no route change, and no
//! real engine. It serves the committed desktop page through Tauri. The page
//! reaches one narrow demo command. The bridge checks every method and path
//! against a fixed allowlist. The native menu calls fixed page actions.

use hotspotshade_desktop::bridge::DemoBridge;
use hotspotshade_desktop::commands;
use hotspotshade_desktop::menu;
use hotspotshade_desktop::window;

fn main() {
    tauri::Builder::default()
        .manage(DemoBridge::new())
        .invoke_handler(commands::handler())
        .menu(menu::build)
        .on_menu_event(|app, event| menu::handle(app, event.id().as_ref()))
        .setup(|app| {
            let window = window::builder(app).build()?;
            let _ = window.set_focus();
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running the HotspotShade desktop demo");
}
