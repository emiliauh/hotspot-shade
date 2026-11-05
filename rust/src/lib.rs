//! `hotspotshade`: a target device normalizer for source device hotspot traffic.
//!
//! # Goal
//!
//! Make tethered traffic match native source device traffic at the IP and TTL
//! layer. The target device re-originates every inner flow as one ordinary
//! outer socket with TTL 65. It pins that socket to the physical hotspot
//! interface. The source device NAT decrements the TTL once, so the carrier
//! sees 64, the native source device value. There is no external relay, no VPS,
//! and no VPN protocol. The source device NAT is the terminator. The goal holds
//! on every platform that the project supports. macOS is implemented and
//! verified on a live hotspot. Windows and Linux implement the source device
//! proxy start path, but neither has a live hotspot test.
//!
//! An optional source device proxy app (in `ios/`) serves carriers that throttle
//! the hotspot bearer. It is a separate mode. It never replaces or weakens the
//! direct mode.
//!
//! # Invariants
//!
//! These rules are the reason the design works. See `AGENTS.md` for the full
//! list.
//!
//! - Every outer socket comes from [`normalization`]. Each one sets TTL 65 and
//!   is audited by a TTL read-back. `ttl_bad` must stay 0.
//! - One inner 4-tuple maps to one outer socket. Unrelated flows never share an
//!   outer connection.
//! - DNS never goes through `getaddrinfo()` on an egress path.
//! - IPv6 is blocked by default. `--ipv6 inherit` is an explicit leak.
//! - Cleanup removes every route, address, and device that the process created,
//!   on every exit path.
//! - The tunnel is not fail-closed. More-specific routes and local DNS can
//!   bypass it.
//!
//! # Where to start
//!
//! [`service`] holds the lifecycle for the CLI and the GUI. [`relay`] holds the
//! flow table and the workers. [`tcp`] is the inner TCP endpoint. [`platform`]
//! holds the macOS utun and route code.
//!
//! # Platform boundary
//!
//! The tunnel is implemented on macOS, on Linux in source device proxy mode,
//! and on Windows in source device proxy mode. The Windows path loads a
//! `wintun.dll` that the user installs, uses the native route boundary, and
//! runs the portable relay. A live Windows tunnel is not verified yet. See
//! [`WINDOWS_NOT_IMPLEMENTED`] for the commands that Windows does not provide.

/// Error text for a command that the current platform does not implement.
pub const WINDOWS_NOT_IMPLEMENTED: &str = "The tunnel is not implemented on Windows.";

pub mod autostop;
mod connect_deadline;
pub mod demo;
pub mod desktop_control;
pub mod diagnostics;
pub mod dns;
pub mod environment;
#[cfg(target_os = "linux")]
pub mod environment_linux;
pub mod failures;
pub mod gui;
pub mod packet;
pub mod pairing;
pub mod source_pairing;
pub mod tcp;
pub mod udp_responder;
#[cfg(any(windows, test))]
pub mod windows_native_routes;
#[cfg(any(windows, test))]
pub mod windows_relay_wait;
pub mod windows_route_verify;

#[cfg(unix)]
pub mod gui_backend;
#[cfg(windows)]
pub mod gui_backend_windows;
#[cfg(unix)]
pub mod ipv6;
#[cfg(any(unix, windows))]
pub mod phone;
#[cfg(unix)]
pub mod phone_server;
#[cfg(unix)]
pub mod platform;
#[cfg(windows)]
#[path = "platform_windows.rs"]
pub mod platform;
#[cfg(target_os = "linux")]
pub mod platform_linux;
#[cfg(unix)]
pub mod privileged;
pub mod relay;
pub mod relay_poll;
#[cfg(any(unix, windows))]
pub mod service;
#[cfg(unix)]
pub mod socks;
#[cfg(unix)]
pub mod speed_diag;
#[cfg(unix)]
pub mod udp_diag;

#[cfg(unix)]
pub mod normalization;
#[cfg(windows)]
#[path = "normalization_windows.rs"]
pub mod normalization;
