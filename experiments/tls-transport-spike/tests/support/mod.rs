#![allow(dead_code)]

//! Shared loopback harness for the TLS spike tests.
//!
//! The harness binds an ephemeral address on 127.0.0.1 only. It creates no
//! route, no tunnel device, and no external connection. Every accept, read, and
//! write is bounded so a broken test fails instead of hanging a CI job.

use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use tls_transport_spike::transport::{
    accept_server, assert_tls13, handshake_client, handshake_server, new_client_connection,
    HandshakeDeadline, IO_TIMEOUT,
};

pub use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};

pub fn accept_with_deadline(listener: &TcpListener) -> io::Result<TcpStream> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + IO_TIMEOUT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                listener.set_nonblocking(false)?;
                stream.set_nonblocking(false)?;
                return Ok(stream);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "loopback accept timed out",
                    ));
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error),
        }
    }
}

/// One listener serving `count` TLS sessions on loopback.
pub struct SessionServer<T> {
    pub port: u16,
    pub join: JoinHandle<Vec<io::Result<T>>>,
}

impl<T> SessionServer<T> {
    pub fn finish(self) -> Vec<io::Result<T>> {
        self.join
            .join()
            .expect("server worker thread did not panic")
    }
}

/// Serve `count` sessions. Each accepted connection gets its own worker thread
/// and its own TLS connection. The handler runs only after the handshake and
/// the ALPN check.
pub fn spawn_sessions<T, F>(config: Arc<ServerConfig>, count: usize, handler: F) -> SessionServer<T>
where
    T: Send + 'static,
    F: Fn(usize, &mut TcpStream, &mut ServerConnection) -> io::Result<T> + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let port = listener.local_addr().expect("local address").port();
    let handler = Arc::new(handler);

    let join = thread::spawn(move || {
        let mut workers = Vec::with_capacity(count);
        for index in 0..count {
            let mut stream = match accept_with_deadline(&listener) {
                Ok(stream) => stream,
                Err(error) => {
                    // Fill the remaining slots with the same bounded failure.
                    // Tests keep their index checks without waiting forever.
                    let kind = error.kind();
                    let message = error.to_string();
                    for _ in index..count {
                        let message = message.clone();
                        workers.push(thread::spawn(move || Err(io::Error::new(kind, message))));
                    }
                    break;
                }
            };
            if let Err(error) = tls_transport_spike::transport::tune(&stream) {
                let kind = error.kind();
                let message = error.to_string();
                workers.push(thread::spawn(move || Err(io::Error::new(kind, message))));
                continue;
            }
            let config = config.clone();
            let handler = handler.clone();
            workers.push(thread::spawn(move || {
                // One deadline covers the ClientHello read and the rest of the
                // handshake, not one budget per helper call.
                let deadline = HandshakeDeadline::default_policy();
                let mut conn = accept_server(&mut stream, config, &deadline)?;
                handshake_server(&mut conn, &mut stream, &deadline)?;
                handler(index, &mut stream, &mut conn)
            }));
        }
        workers
            .into_iter()
            .map(|worker| worker.join().expect("session worker did not panic"))
            .collect()
    });

    SessionServer { port, join }
}

/// Connect to the loopback server and run the client handshake, but do not
/// assert the negotiated values. The client handshake enforces the ALPN policy.
pub fn connect_unchecked(
    port: u16,
    config: Arc<ClientConfig>,
) -> io::Result<(TcpStream, ClientConnection)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    tls_transport_spike::transport::tune(&stream)?;
    let mut conn = new_client_connection(config)?;
    handshake_client(&mut conn, &mut stream, &HandshakeDeadline::default_policy())?;
    Ok((stream, conn))
}

/// Connect to the loopback server and run the client handshake.
///
/// TLS 1.3 and the ALPN label are enforced by the library handshake helpers,
/// not by this harness.
pub fn connect(port: u16, config: Arc<ClientConfig>) -> io::Result<(TcpStream, ClientConnection)> {
    let (stream, conn) = connect_unchecked(port, config)?;
    assert_tls13(conn.protocol_version());
    Ok((stream, conn))
}

/// Connect a raw TCP socket without TLS. Used for cleartext rejection tests.
pub fn connect_raw(port: u16) -> io::Result<TcpStream> {
    let stream = TcpStream::connect(("127.0.0.1", port))?;
    tls_transport_spike::transport::tune(&stream)?;
    Ok(stream)
}

/// Deterministic bytes for byte-exact connection checks. No real traffic.
pub fn payload(len: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.push((state & 0xff) as u8);
    }
    out
}
