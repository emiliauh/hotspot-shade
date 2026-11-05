# Desktop icon

`icon.png` is a copy of `assets/logo/mac-icon-1024.png`. Tauri needs an icon
even when the bundle is inactive. Replace this file when the product icon
changes. Do not change the source file in `assets/logo/` for this prototype.

`icon.ico` is generated from `assets/logo/mac-icon-256.png` with
`sips -s format ico`. Windows builds need this file even when bundling is off.
