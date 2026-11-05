//! Native menu for the desktop demo.
//!
//! The menu is part of the Tauri window shell. It has no plugin and no new
//! permission. Navigation and refresh actions call one fixed page function.
//! Window actions use the Tauri window API. The menu cannot reach the real
//! service, name a URL, or pass user text to a script.

use tauri::menu::{Menu, MenuItem, SubmenuBuilder};
use tauri::{AppHandle, Manager, Runtime};

#[cfg(target_os = "macos")]
use tauri::menu::AboutMetadata;

/// The identifier of the one demo window.
pub const MAIN_WINDOW: &str = "main";

/// One fixed menu action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MenuAction {
    Dashboard,
    Activity,
    Settings,
    Advanced,
    Refresh,
    CheckNow,
    Theme,
    Minimize,
    Zoom,
    Close,
    Quit,
}

/// Map a menu identifier to one action. An unknown identifier gets no action.
pub fn action_for(id: &str) -> Option<MenuAction> {
    Some(match id {
        "view.dashboard" => MenuAction::Dashboard,
        "view.activity" => MenuAction::Activity,
        "view.settings" => MenuAction::Settings,
        "help.demo" => MenuAction::Advanced,
        "view.refresh" => MenuAction::Refresh,
        "view.check_now" => MenuAction::CheckNow,
        "view.theme" => MenuAction::Theme,
        "window.minimize" => MenuAction::Minimize,
        "window.zoom" => MenuAction::Zoom,
        "window.close" => MenuAction::Close,
        "app.quit" => MenuAction::Quit,
        _ => return None,
    })
}

/// The fixed page call for a menu action. Window actions return None.
pub fn script_for(action: MenuAction) -> Option<&'static str> {
    Some(match action {
        MenuAction::Dashboard => {
            "window.__hotspotshadeMenu&&window.__hotspotshadeMenu('dashboard')"
        }
        MenuAction::Activity => "window.__hotspotshadeMenu&&window.__hotspotshadeMenu('activity')",
        MenuAction::Settings => "window.__hotspotshadeMenu&&window.__hotspotshadeMenu('settings')",
        MenuAction::Advanced => "window.__hotspotshadeMenu&&window.__hotspotshadeMenu('advanced')",
        MenuAction::Refresh => "window.__hotspotshadeMenu&&window.__hotspotshadeMenu('refresh')",
        MenuAction::CheckNow => "window.__hotspotshadeMenu&&window.__hotspotshadeMenu('check-now')",
        MenuAction::Theme => "window.__hotspotshadeMenu&&window.__hotspotshadeMenu('theme')",
        MenuAction::Minimize | MenuAction::Zoom | MenuAction::Close | MenuAction::Quit => {
            return None
        }
    })
}

/// Run one menu action.
pub fn handle<R: Runtime>(app: &AppHandle<R>, id: &str) {
    let Some(action) = action_for(id) else {
        return;
    };
    match action {
        MenuAction::Minimize => {
            if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
                let _ = window.minimize();
            }
        }
        MenuAction::Zoom => {
            if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
                if window.is_maximized().unwrap_or(false) {
                    let _ = window.unmaximize();
                } else {
                    let _ = window.maximize();
                }
            }
        }
        MenuAction::Close => {
            if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
                let _ = window.close();
            }
        }
        MenuAction::Quit => app.exit(0),
        _ => {
            if let Some(script) = script_for(action) {
                if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
                    let _ = window.eval(script);
                }
            }
        }
    }
}

/// Build the native menu.
///
/// macOS gets the standard application menu. Windows and Linux get a File menu
/// with the same settings and quit actions. Every platform gets View, Window,
/// and Help menus. The actions are fixed. The page never receives arbitrary
/// menu text.
pub fn build<R: Runtime, M: Manager<R>>(manager: &M) -> tauri::Result<Menu<R>> {
    let dashboard = MenuItem::with_id(
        manager,
        "view.dashboard",
        "Dashboard",
        true,
        Some("CmdOrCtrl+1"),
    )?;
    let activity = MenuItem::with_id(
        manager,
        "view.activity",
        "Activity",
        true,
        Some("CmdOrCtrl+2"),
    )?;
    let settings = MenuItem::with_id(
        manager,
        "view.settings",
        "Settings...",
        true,
        Some("CmdOrCtrl+,"),
    )?;
    let refresh = MenuItem::with_id(
        manager,
        "view.refresh",
        "Refresh Status",
        true,
        Some("CmdOrCtrl+R"),
    )?;
    let check_now = MenuItem::with_id(
        manager,
        "view.check_now",
        "Check Source Device Now",
        true,
        Some("CmdOrCtrl+Shift+K"),
    )?;
    let theme = MenuItem::with_id(
        manager,
        "view.theme",
        "Toggle Appearance",
        true,
        Some("CmdOrCtrl+Shift+L"),
    )?;
    let minimize = MenuItem::with_id(
        manager,
        "window.minimize",
        "Minimize",
        true,
        Some("CmdOrCtrl+M"),
    )?;
    let zoom = MenuItem::with_id(manager, "window.zoom", "Zoom", true, None::<&str>)?;
    let close = MenuItem::with_id(
        manager,
        "window.close",
        "Close Window",
        true,
        Some("CmdOrCtrl+W"),
    )?;
    let demo_limits =
        MenuItem::with_id(manager, "help.demo", "Demo Limitations", true, None::<&str>)?;

    let view_menu = SubmenuBuilder::new(manager, "View")
        .item(&dashboard)
        .item(&activity)
        .separator()
        .item(&refresh)
        .item(&check_now)
        .separator()
        .item(&theme)
        .build()?;

    let window_menu = SubmenuBuilder::new(manager, "Window")
        .item(&minimize)
        .item(&zoom)
        .separator()
        .item(&close)
        .build()?;

    let help_menu = SubmenuBuilder::new(manager, "Help")
        .item(&demo_limits)
        .build()?;

    #[cfg(target_os = "macos")]
    let edit_menu = SubmenuBuilder::new(manager, "Edit")
        .undo()
        .redo()
        .separator()
        .cut()
        .copy()
        .paste()
        .select_all()
        .build()?;

    #[cfg(not(target_os = "macos"))]
    let edit_menu = SubmenuBuilder::new(manager, "Edit")
        .cut()
        .copy()
        .paste()
        .select_all()
        .build()?;

    #[cfg(target_os = "macos")]
    {
        let about = AboutMetadata {
            name: Some("HotspotShade Desktop (Demo)".into()),
            version: Some(env!("CARGO_PKG_VERSION").into()),
            short_version: Some(env!("CARGO_PKG_VERSION").into()),
            comments: Some("Demo only. No tunnel, routes, or network traffic.".into()),
            ..AboutMetadata::default()
        };
        let app_menu = SubmenuBuilder::new(manager, "HotspotShade Desktop")
            .about_with_text("About HotspotShade Desktop", Some(about))
            .separator()
            .item(&settings)
            .separator()
            .services()
            .separator()
            .hide_with_text("Hide HotspotShade Desktop")
            .hide_others_with_text("Hide Others")
            .show_all_with_text("Show All")
            .separator()
            .quit_with_text("Quit HotspotShade Desktop")
            .build()?;
        Menu::with_items(
            manager,
            &[&app_menu, &edit_menu, &view_menu, &window_menu, &help_menu],
        )
    }

    #[cfg(not(target_os = "macos"))]
    {
        let quit = MenuItem::with_id(
            manager,
            "app.quit",
            "Quit HotspotShade Desktop",
            true,
            Some("CmdOrCtrl+Q"),
        )?;
        let file_menu = SubmenuBuilder::new(manager, "File")
            .item(&settings)
            .separator()
            .item(&quit)
            .build()?;
        Menu::with_items(
            manager,
            &[&file_menu, &edit_menu, &view_menu, &window_menu, &help_menu],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_menu_id_maps_to_one_action() {
        for id in [
            "view.dashboard",
            "view.activity",
            "view.settings",
            "help.demo",
            "view.refresh",
            "view.check_now",
            "view.theme",
            "window.minimize",
            "window.zoom",
            "window.close",
            "app.quit",
        ] {
            assert!(action_for(id).is_some(), "{id}");
        }
        assert_eq!(action_for("view.unknown"), None);
        assert_eq!(action_for(""), None);
    }

    #[test]
    fn page_scripts_hold_fixed_actions_only() {
        for action in [
            MenuAction::Dashboard,
            MenuAction::Activity,
            MenuAction::Settings,
            MenuAction::Advanced,
            MenuAction::Refresh,
            MenuAction::CheckNow,
            MenuAction::Theme,
        ] {
            let script = script_for(action).expect("page action");
            assert!(script.starts_with("window.__hotspotshadeMenu&&window.__hotspotshadeMenu('"));
            assert!(!script.contains('"'));
            assert!(!script.contains('`'));
            assert!(!script.contains('\\'));
        }
        for action in [
            MenuAction::Minimize,
            MenuAction::Zoom,
            MenuAction::Close,
            MenuAction::Quit,
        ] {
            assert_eq!(script_for(action), None);
        }
    }
}
