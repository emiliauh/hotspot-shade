//! Portable hermetic mock source device for integration tests.
//!
//! Every listener binds to `127.0.0.1`. No script opens a route, a TUN
//! device, or a socket to another host. Each script has a bounded read
//! timeout and a stop flag. `stop` is idempotent and joins every handler
//! thread.
//!
//! This module is shared by the integration test targets. It is not a test
//! target itself.

#![allow(dead_code)]

pub mod pairing;
pub mod socks;

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// The fixed public test user. It is not a secret.
pub const TEST_USER: &str = "hotspotshade";
/// The fixed public test token. It is not a secret.
pub const TEST_TOKEN: &str = "test-token-0123456789abcdef";
/// The loopback address that a mock source device reports as its host.
pub const TEST_HOST: Ipv4Addr = Ipv4Addr::LOCALHOST;
/// The fixed test proxy port. No listener uses this port.
pub const TEST_PHONE_PORT: u16 = 1080;
/// A domain that the source device proxy receives unchanged. No lookup runs.
pub const TEST_DOMAIN: &str = "example.test";
/// A documentation address. The mock never connects to it.
pub const DOC_IPV4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
/// A documentation address. The mock never connects to it.
pub const DOC_IPV6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0010);

const READ_TIMEOUT: Duration = Duration::from_secs(5);
const STOP_SLICE: Duration = Duration::from_millis(10);
const WAKE_TIMEOUT: Duration = Duration::from_millis(500);

/// A small event log with a bounded wait. A test can wait for one protocol
/// phase without polling.
pub struct EventLog<E> {
    events: Mutex<Vec<E>>,
    ready: Condvar,
}

impl<E> Default for EventLog<E> {
    fn default() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            ready: Condvar::new(),
        }
    }
}

impl<E: Copy + Eq> EventLog<E> {
    /// Record one event. A repeated event is kept once.
    pub fn record(&self, event: E) {
        let mut events = self.events.lock().unwrap();
        if !events.contains(&event) {
            events.push(event);
        }
        self.ready.notify_all();
    }

    /// Wait until the event is present or the limit expires.
    pub fn wait_for(&self, event: E, limit: Duration) -> bool {
        let events = self.events.lock().unwrap();
        let (events, _) = self
            .ready
            .wait_timeout_while(events, limit, |events| !events.contains(&event))
            .unwrap();
        events.contains(&event)
    }

    pub fn contains(&self, event: E) -> bool {
        self.events.lock().unwrap().contains(&event)
    }
}

/// The result of stopping one mock server.
#[derive(Debug)]
pub struct MockReport {
    pub connections: usize,
    pub failures: Vec<String>,
}

impl MockReport {
    /// Panic when a script failed or a connection has no record.
    pub fn assert_clean(&self) {
        assert!(
            self.failures.is_empty(),
            "mock source device failures: {:#?}",
            self.failures
        );
    }
}

/// A loopback listener with deterministic cleanup.
pub struct MockServer {
    address: SocketAddr,
    shared: Arc<Shared>,
    accept: Option<JoinHandle<()>>,
}

struct Shared {
    stop: AtomicBool,
    next: AtomicUsize,
    connections: Mutex<HashMap<usize, TcpStream>>,
    handlers: Mutex<Vec<JoinHandle<()>>>,
    failures: Mutex<Vec<String>>,
}

type Script = dyn Fn(&mut MockConnection) -> Result<(), String> + Send + Sync;

impl MockServer {
    /// Bind `127.0.0.1:0` and run `script` for each accepted connection.
    pub fn start<F>(script: F) -> io::Result<Self>
    where
        F: Fn(&mut MockConnection) -> Result<(), String> + Send + Sync + 'static,
    {
        Self::start_on((Ipv4Addr::LOCALHOST, 0).into(), script)
    }

    /// Bind `address` and run `script` for each accepted connection.
    ///
    /// A Linux tunnel test binds the mock on a non-local address behind a veth
    /// pair. The default [`MockServer::start`] stays on loopback.
    pub fn start_on<F>(address: SocketAddr, script: F) -> io::Result<Self>
    where
        F: Fn(&mut MockConnection) -> Result<(), String> + Send + Sync + 'static,
    {
        let listener = TcpListener::bind(address)?;
        let address = listener.local_addr()?;
        let shared = Arc::new(Shared {
            stop: AtomicBool::new(false),
            next: AtomicUsize::new(0),
            connections: Mutex::new(HashMap::new()),
            handlers: Mutex::new(Vec::new()),
            failures: Mutex::new(Vec::new()),
        });
        let script: Arc<Script> = Arc::new(script);
        let accept_shared = Arc::clone(&shared);
        let accept = thread::Builder::new()
            .name("mock-source-accept".into())
            .spawn(move || loop {
                match listener.accept() {
                    Ok((stream, _peer)) => {
                        if accept_shared.stop.load(Ordering::Acquire) {
                            let _ = stream.shutdown(Shutdown::Both);
                            break;
                        }
                        let index = accept_shared.next.fetch_add(1, Ordering::AcqRel);
                        let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
                        let _ = stream.set_write_timeout(Some(READ_TIMEOUT));
                        let _ = stream.set_nodelay(true);
                        if let Ok(clone) = stream.try_clone() {
                            accept_shared
                                .connections
                                .lock()
                                .unwrap()
                                .insert(index, clone);
                        }
                        let handler_script = Arc::clone(&script);
                        let handler_shared = Arc::clone(&accept_shared);
                        let spawned = thread::Builder::new()
                            .name(format!("mock-source-{index}"))
                            .spawn(move || {
                                let mut connection = MockConnection {
                                    stream,
                                    index,
                                    shared: Arc::clone(&handler_shared),
                                };
                                match catch_unwind(AssertUnwindSafe(|| {
                                    handler_script(&mut connection)
                                })) {
                                    Ok(Ok(())) => {}
                                    Ok(Err(message)) => handler_shared
                                        .failures
                                        .lock()
                                        .unwrap()
                                        .push(format!("connection {index}: {message}")),
                                    Err(_) => handler_shared
                                        .failures
                                        .lock()
                                        .unwrap()
                                        .push(format!("connection {index}: script panicked")),
                                }
                                handler_shared.connections.lock().unwrap().remove(&index);
                            });
                        match spawned {
                            Ok(handle) => accept_shared.handlers.lock().unwrap().push(handle),
                            Err(error) => accept_shared
                                .failures
                                .lock()
                                .unwrap()
                                .push(format!("connection {index}: spawn failed: {error}")),
                        }
                    }
                    Err(error) => {
                        if !accept_shared.stop.load(Ordering::Acquire) {
                            accept_shared
                                .failures
                                .lock()
                                .unwrap()
                                .push(format!("accept failed: {error}"));
                        }
                        break;
                    }
                }
            })?;
        Ok(Self {
            address,
            shared,
            accept: Some(accept),
        })
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Count the connections that the listener accepted.
    pub fn connections(&self) -> usize {
        self.shared.next.load(Ordering::Acquire)
    }

    /// Stop the listener and every handler. This call is idempotent.
    pub fn stop(&mut self) -> MockReport {
        self.stop_inner()
    }

    fn stop_inner(&mut self) -> MockReport {
        if !self.shared.stop.swap(true, Ordering::AcqRel) {
            // Wake a blocking accept call. The accept loop sees the stop flag
            // before it registers the new connection.
            let _ = TcpStream::connect_timeout(&self.address, WAKE_TIMEOUT);
        }
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
        let streams: Vec<TcpStream> = self
            .shared
            .connections
            .lock()
            .unwrap()
            .values()
            .filter_map(|stream| stream.try_clone().ok())
            .collect();
        for stream in &streams {
            let _ = stream.shutdown(Shutdown::Both);
        }
        let handlers = std::mem::take(&mut *self.shared.handlers.lock().unwrap());
        for handler in handlers {
            let _ = handler.join();
        }
        let report = MockReport {
            connections: self.shared.next.load(Ordering::Acquire),
            failures: self.shared.failures.lock().unwrap().clone(),
        };
        self.shared.connections.lock().unwrap().clear();
        report
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        let _ = self.stop_inner();
    }
}

/// One accepted loopback connection. All reads and writes have a bound.
pub struct MockConnection {
    stream: TcpStream,
    index: usize,
    shared: Arc<Shared>,
}

impl MockConnection {
    pub fn index(&self) -> usize {
        self.index
    }

    pub fn stream(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    pub fn stopped(&self) -> bool {
        self.shared.stop.load(Ordering::Acquire)
    }

    pub fn shutdown(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }

    /// Build one error line for a test failure.
    pub fn error(&self, phase: &str, detail: impl std::fmt::Display) -> String {
        format!("connection {}: {phase}: {detail}", self.index)
    }

    /// Read exactly `bytes`. Return false when the peer closed before the
    /// first byte.
    pub fn read_exact_allow_eof(&mut self, bytes: &mut [u8], phase: &str) -> Result<bool, String> {
        let mut offset = 0;
        while offset < bytes.len() {
            match self.stream.read(&mut bytes[offset..]) {
                Ok(0) if offset == 0 => return Ok(false),
                Ok(0) => return Err(self.error(phase, "peer closed inside a field")),
                Ok(count) => offset += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(self.error(phase, error)),
            }
        }
        Ok(true)
    }

    /// Read exactly `bytes`. A clean close before the first byte is an error.
    pub fn read_exact(&mut self, bytes: &mut [u8], phase: &str) -> Result<(), String> {
        if self.read_exact_allow_eof(bytes, phase)? {
            Ok(())
        } else {
            Err(self.error(phase, "peer closed before the field"))
        }
    }

    pub fn write_all(&mut self, bytes: &[u8], phase: &str) -> Result<(), String> {
        self.stream
            .write_all(bytes)
            .map_err(|error| self.error(phase, error))
    }

    /// Read one u16 big-endian length and its payload. Return None on a clean
    /// close before the length.
    pub fn read_frame(&mut self, max: usize, phase: &str) -> Result<Option<Vec<u8>>, String> {
        let mut header = [0u8; 2];
        if !self.read_exact_allow_eof(&mut header, phase)? {
            return Ok(None);
        }
        let length = u16::from_be_bytes(header) as usize;
        if length == 0 || length > max {
            return Err(self.error(phase, format!("invalid frame length {length}")));
        }
        let mut payload = vec![0u8; length];
        if !self.read_exact_allow_eof(&mut payload, phase)? {
            return Err(self.error(phase, "peer closed inside a frame"));
        }
        Ok(Some(payload))
    }

    pub fn write_frame(&mut self, payload: &[u8], phase: &str) -> Result<(), String> {
        let length =
            u16::try_from(payload.len()).map_err(|_| self.error(phase, "frame is too large"))?;
        self.write_all(&length.to_be_bytes(), phase)?;
        self.write_all(payload, phase)
    }

    /// Wait until the server stop flag is set or the limit expires.
    pub fn wait_stopped(&self, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        while Instant::now() < deadline {
            if self.stopped() {
                return true;
            }
            thread::sleep(STOP_SLICE);
        }
        self.stopped()
    }

    /// Wait for the peer to close. Data is discarded. Return false on the
    /// limit, and on a server stop.
    pub fn wait_for_peer_close(&mut self, limit: Duration) -> Result<bool, String> {
        let previous = self.stream.read_timeout().unwrap_or(Some(READ_TIMEOUT));
        self.stream
            .set_read_timeout(Some(STOP_SLICE))
            .map_err(|error| self.error("wait for peer close", error))?;
        let deadline = Instant::now() + limit;
        let mut byte = [0u8; 1];
        let result = loop {
            if Instant::now() >= deadline || self.stopped() {
                break Ok(false);
            }
            match self.stream.read(&mut byte) {
                Ok(0) => break Ok(true),
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                // A peer that closes with unread data can send a reset. The
                // flow is gone, which is what this wait checks.
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                    ) =>
                {
                    break Ok(true)
                }
                Err(error) => break Err(self.error("wait for peer close", error)),
            }
        };
        let _ = self.stream.set_read_timeout(previous);
        result
    }
}
