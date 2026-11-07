//! Byte-exact transport over one TLS connection, and one TLS connection per
//! simulated flow.
//!
//! These tests do not run a proxy relay. There is no inner socket and no
//! forwarding loop: a handler reads from one TLS stream and writes back to the
//! same stream. A production relay needs its own half-close, backpressure, and
//! idle policy, none of which this spike implements.

mod support;

use std::collections::HashSet;
use std::thread;

use support::{connect, payload, spawn_sessions};
use tls_transport_spike::transport::{client_config, read_exact_plain, server_config, write_plain};
use tls_transport_spike::TestIdentity;

#[test]
fn large_bidirectional_transfer_is_byte_exact() {
    let server = TestIdentity::server();
    let client = TestIdentity::client();
    let server_tls = server_config(&server, client.spki_pin);
    let client_tls = client_config(&client, server.spki_pin);

    let greeting = payload(32 * 1024);
    let body = payload(256 * 1024);
    let expected_body = body.clone();
    let expected_greeting = greeting.clone();
    let server_greeting = greeting.clone();
    let server_body = body.clone();

    let sessions = spawn_sessions(server_tls.config, 1, move |_, stream, conn| {
        // Write in one direction while the peer is writing in the other.
        write_plain(conn, stream, &server_greeting)?;
        let mut received = vec![0u8; server_body.len()];
        read_exact_plain(conn, stream, &mut received)?;
        assert!(
            received == server_body,
            "server must receive the exact bytes"
        );
        write_plain(conn, stream, &received)?;
        Ok(())
    });

    let (mut stream, mut conn) = connect(sessions.port, client_tls).expect("client handshake");
    write_plain(&mut conn, &mut stream, &body).expect("client body write");

    let mut greeting_in = vec![0u8; greeting.len()];
    read_exact_plain(&mut conn, &mut stream, &mut greeting_in).expect("client greeting read");
    assert!(
        greeting_in == expected_greeting,
        "server greeting must be byte exact"
    );

    let mut body_in = vec![0u8; body.len()];
    read_exact_plain(&mut conn, &mut stream, &mut body_in).expect("client echo read");
    assert!(
        body_in == expected_body,
        "echoed body must be byte exact in both directions"
    );

    sessions.finish()[0].as_ref().expect("server session");
}

#[test]
fn chunked_ping_pong_is_byte_exact() {
    let server = TestIdentity::server();
    let client = TestIdentity::client();
    let server_tls = server_config(&server, client.spki_pin);
    let client_tls = client_config(&client, server.spki_pin);

    let body = payload(1024 * 1024 + 7);
    let chunk = 16 * 1024;
    let expected = body.clone();
    let server_body = body.clone();

    let sessions = spawn_sessions(server_tls.config, 1, move |_, stream, conn| {
        let mut received = Vec::new();
        let mut buf = vec![0u8; chunk];
        loop {
            let remaining = server_body.len() - received.len();
            if remaining == 0 {
                break;
            }
            let want = remaining.min(chunk);
            read_exact_plain(conn, stream, &mut buf[..want])?;
            received.extend_from_slice(&buf[..want]);
            write_plain(conn, stream, &buf[..want])?;
        }
        assert!(
            received == server_body,
            "server must accumulate exact bytes"
        );
        Ok(())
    });

    let (mut stream, mut conn) = connect(sessions.port, client_tls).expect("client handshake");
    let mut offset = 0;
    let mut echo = vec![0u8; chunk];
    while offset < body.len() {
        let want = (body.len() - offset).min(chunk);
        write_plain(&mut conn, &mut stream, &body[offset..offset + want]).expect("client write");
        read_exact_plain(&mut conn, &mut stream, &mut echo[..want]).expect("client echo read");
        assert_eq!(&echo[..want], &expected[offset..offset + want]);
        offset += want;
    }

    sessions.finish()[0].as_ref().expect("server session");
}

#[test]
fn each_flow_gets_its_own_tls_connection() {
    const FLOWS: usize = 8;

    let server = TestIdentity::server();
    let client = TestIdentity::client();
    let server_tls = server_config(&server, client.spki_pin);
    let client_tls = client_config(&client, server.spki_pin);

    let sessions = spawn_sessions(server_tls.config, FLOWS, |_, stream, conn| {
        let peer_port = stream.peer_addr()?.port();
        let mut id = [0u8; 8];
        read_exact_plain(conn, stream, &mut id)?;
        let mut body = vec![0u8; 4096];
        read_exact_plain(conn, stream, &mut body)?;
        write_plain(conn, stream, &id)?;
        write_plain(conn, stream, &body)?;
        Ok(peer_port)
    });

    let mut clients = Vec::new();
    for flow in 0..FLOWS {
        let config = client_tls.clone();
        let port = sessions.port;
        clients.push(thread::spawn(move || {
            let (mut stream, mut conn) = connect(port, config).expect("per-flow handshake");
            let mut id = [0u8; 8];
            id[..4].copy_from_slice(&(flow as u32).to_be_bytes());
            id[4..].copy_from_slice(&(flow as u32 ^ 0xa5a5_a5a5).to_be_bytes());
            let body = payload(4096);
            write_plain(&mut conn, &mut stream, &id).expect("flow id");
            write_plain(&mut conn, &mut stream, &body).expect("flow body");

            let mut id_in = [0u8; 8];
            read_exact_plain(&mut conn, &mut stream, &mut id_in).expect("flow id echo");
            assert_eq!(id_in, id);

            let mut body_in = vec![0u8; body.len()];
            read_exact_plain(&mut conn, &mut stream, &mut body_in).expect("flow body echo");
            assert!(
                body_in == body,
                "flow {flow} body must not cross another flow"
            );
        }));
    }

    for handle in clients {
        handle.join().expect("client flow thread");
    }

    let ports: Vec<u16> = sessions
        .finish()
        .into_iter()
        .map(|result| result.expect("each server flow"))
        .collect();
    assert_eq!(ports.len(), FLOWS);
    let unique: HashSet<u16> = ports.iter().copied().collect();
    assert_eq!(
        unique.len(),
        FLOWS,
        "every inner flow must use one distinct outer TCP connection"
    );
}
