//! Test-only authenticated encrypted transport spike.
//!
//! This crate is an isolated experiment. It is not built by the engine, the
//! GUI, or any app. It uses rustls for TLS 1.3 and pins one server key and one
//! client key for each pair. It opens loopback TCP connections only.
//!
//! Read `README.md` in this directory before treating any result as guidance.
//! This code has not had an independent cryptographic review and is not a
//! production protocol.

pub mod identity;
pub mod transport;

pub use identity::{certificate_spki, Pin, TestIdentity};
