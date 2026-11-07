//! Bounded handshake tests.
//!
//! The socket timeout bounds one read or write. A peer that drips one byte at a
//! time resets that timer, so these tests exercise the separate absolute
//! deadline in `HandshakeDeadline`. A short budget keeps the suite fast; the
//! default policy budget is ten seconds.

mod support;

use std::io::{self, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use support::spawn_sessions;
use tls_transport_spike::transport::{
    accept_server, client_config, handshake_client, new_client_connection, server_config, tune,
    HandshakeDeadline, RecordingWriter, HANDSHAKE_DEADLINE,
};
use tls_transport_spike::TestIdentity;

/// Short budget for the negative tests. A correct implementation fails close to
/// this value and never waits for the ten second per-I/O timeout.
const SHORT_BUDGET: Duration = Duration::from_millis(400);

/// Slack for scheduling and the final timeout rounding.
const SLACK: Duration = Duration::from_secs(2);

fn assert_deadline_shape(elapsed: Duration) {
    assert!(
        elapsed >= SHORT_BUDGET - Duration::from_millis(50),
        "handshake failed before the budget was used: {elapsed:?}"
    );
    assert!(
        elapsed < SHORT_BUDGET + SLACK,
        "handshake exceeded the total deadline by too much: {elapsed:?}"
    );
}

#[test]
fn stalled_client_hello_hits_the_total_deadline() {
    let server = TestIdentity::server();
    let client = TestIdentity::client();
    let server_tls = server_config(&server, client.spki_pin);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let port = listener
        .local_addr()
        .expect("listener local address")
        .port();
    let worker = thread::spawn(move || {
        let mut stream = support::accept_with_deadline(&listener).expect("accept client");
        tune(&stream).expect("server socket options");
        let started = Instant::now();
        let result = accept_server(
            &mut stream,
            server_tls.config,
            &HandshakeDeadline::new(SHORT_BUDGET),
        )
        .map(|_| ());
        (started.elapsed(), result)
    });

    let stream = TcpStream::connect(("127.0.0.1", port)).expect("client connect");
    tune(&stream).expect("client socket options");

    let (elapsed, result) = worker.join().expect("server worker did not panic");
    let error = result.expect_err("a silent client must not complete a handshake");
    assert_eq!(
        error.kind(),
        io::ErrorKind::TimedOut,
        "unexpected error: {error}"
    );
    assert_deadline_shape(elapsed);
    drop(stream);
}

#[test]
fn slow_drip_client_hello_does_not_extend_the_total_deadline() {
    let server = TestIdentity::server();
    let client = TestIdentity::client();
    let server_tls = server_config(&server, client.spki_pin);

    // Capture one real ClientHello without completing a handshake.
    let mut conn =
        new_client_connection(client_config(&client, server.spki_pin)).expect("client connection");
    let mut hello = Vec::new();
    {
        let mut recorder = RecordingWriter::new(&mut hello);
        while conn.wants_write() {
            conn.write_tls(&mut recorder).expect("record ClientHello");
        }
        recorder.flush().expect("flush ClientHello");
    }
    assert!(hello.len() > 64, "captured ClientHello is too short");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let port = listener
        .local_addr()
        .expect("listener local address")
        .port();
    let worker = thread::spawn(move || {
        let mut stream = support::accept_with_deadline(&listener).expect("accept client");
        tune(&stream).expect("server socket options");
        let started = Instant::now();
        let result = accept_server(
            &mut stream,
            server_tls.config,
            &HandshakeDeadline::new(SHORT_BUDGET),
        )
        .map(|_| ());
        (started.elapsed(), result)
    });

    let drip = thread::spawn(move || {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("drip client connect");
        tune(&stream).expect("client socket options");
        // Send the record header, then one payload byte at a time. Each write
        // resets the kernel read timer on the server side.
        if stream.write_all(&hello[..5]).is_err() {
            return;
        }
        for byte in &hello[5..] {
            if stream.write_all(std::slice::from_ref(byte)).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
    });

    let (elapsed, result) = worker.join().expect("server worker did not panic");
    let error = result.expect_err("a slow-drip client must not complete a handshake");
    assert_eq!(
        error.kind(),
        io::ErrorKind::TimedOut,
        "unexpected error: {error}"
    );
    assert_deadline_shape(elapsed);
    // The drip writer stops when the server closes its end.
    let _ = drip.join();
}

#[test]
fn stalled_server_hits_the_client_total_deadline() {
    let server = TestIdentity::server();
    let client = TestIdentity::client();
    let client_tls = client_config(&client, server.spki_pin);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let port = listener
        .local_addr()
        .expect("listener local address")
        .port();
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let worker = thread::spawn(move || {
        let stream = support::accept_with_deadline(&listener).expect("accept client");
        // Hold the connection open and send nothing. The test releases this
        // thread once the client deadline has been observed.
        let _ = stop_rx.recv_timeout(SHORT_BUDGET + SLACK);
        drop(stream);
    });

    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("client connect");
    tune(&stream).expect("client socket options");
    let mut conn = new_client_connection(client_tls).expect("client connection");
    let started = Instant::now();
    let result = handshake_client(
        &mut conn,
        &mut stream,
        &HandshakeDeadline::new(SHORT_BUDGET),
    );
    let elapsed = started.elapsed();

    let error = result.expect_err("a silent server must not complete a handshake");
    assert_eq!(
        error.kind(),
        io::ErrorKind::TimedOut,
        "unexpected error: {error}"
    );
    assert_deadline_shape(elapsed);
    let _ = stop_tx.send(());
    worker.join().expect("server worker did not panic");
}

#[test]
fn normal_handshake_finishes_well_inside_the_default_deadline() {
    assert_eq!(HANDSHAKE_DEADLINE, Duration::from_secs(10));

    let server = TestIdentity::server();
    let client = TestIdentity::client();
    let server_tls = server_config(&server, client.spki_pin);
    let client_tls = client_config(&client, server.spki_pin);

    let sessions = spawn_sessions(server_tls.config, 1, |_, _, _| Ok(()));
    let started = Instant::now();
    let _ = support::connect(sessions.port, client_tls).expect("client handshake");
    let elapsed = started.elapsed();
    sessions.finish()[0].as_ref().expect("server session");

    assert!(
        elapsed < HANDSHAKE_DEADLINE / 2,
        "a loopback handshake should use much less than the total deadline: {elapsed:?}"
    );
}
