//! Shared Rust desktop shell for the HotspotShade demo.
//!
//! This crate is a labeled demo only. It has no tunnel, no route change, and no
//! real engine. It serves the committed desktop page through the Tauri asset
//! protocol. One narrow command connects the page to the in-memory demo
//! backend. The native menu calls fixed page actions.
//!
//! The page cannot name a URL, host, port, token, or command. The bridge checks
//! every method and path against a fixed allowlist. The navigation allowlist
//! keeps the webview on the embedded asset origin.

pub mod bridge;
pub mod commands;
pub mod menu;
pub mod navigation;
pub mod window;
