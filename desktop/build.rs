//! Build the Tauri desktop demo.
//!
//! The page assets are committed under `ui/` and use only local files. This
//! script does not copy the local web GUI from `gui_assets/`. The desktop demo
//! has its own layout. Tauri needs this build script for its generated context,
//! platform metadata, and Windows resources.

fn main() {
    for name in [
        "index.html",
        "styles.css",
        "app.js",
        "model.js",
        "boot.js",
        "favicon.svg",
    ] {
        println!("cargo:rerun-if-changed=ui/{name}");
    }
    tauri_build::build();
}
