//! A hermetic source device SOCKS5 emulator.
//!
//! The emulator answers the real target device client. It authenticates with
//! the fixed public test credentials, accepts one TCP CONNECT or the private
//! UDP-over-TCP command, and carries framed datagrams. Fault scripts stop at
//! one bounded phase. The emulator never connects to the requested target.

use super::{EventLog, MockConnection, MockReport, MockServer, TEST_TOKEN, TEST_USER};
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The private source device UDP command. The target device client sends it.
pub const UDP_COMMAND: u8 = 0x80;
/// The largest datagram that the target device accepts from the source device.
pub const MAX_DATAGRAM: usize = 1472;

/// The fault that one mock connection emulates. Each fault is bounded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocksFault {
    None,
    /// Answer the greeting with "no acceptable method".
    RejectMethod,
    /// Accept the method and reject the username and token.
    RejectCredentials,
    /// Read the greeting and never answer the method choice.
    SilentAfterGreeting,
    /// Close before the method choice.
    CloseBeforeMethodReply,
    /// Write one byte of the two-byte method choice, then close.
    PartialMethodReply,
    /// Accept the method, read the credentials, then close.
    CloseBeforeAuthReply,
    /// Write one byte of the two-byte authentication answer, then close.
    PartialAuthReply,
    /// Authenticate, read the CONNECT request, then close.
    CloseBeforeConnectReply,
    /// Write three bytes of the four-byte CONNECT header, then close.
    PartialConnectReply,
    /// Write each successful reply one byte at a time. This is a valid source
    /// device behavior on a slow link, not a failure.
    FragmentedReplies,
}

/// What the mock source device does after a successful CONNECT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocksPayload {
    /// Echo TCP bytes until the client closes.
    EchoTcp,
    /// Close the accepted TCP flow at once.
    CloseTcp,
    /// Echo this many length-prefixed datagrams, then wait for close.
    UdpEcho { frames: usize },
    /// Read datagrams and never answer.
    UdpSilent,
    /// Reply with a frame longer than the target device accepts.
    UdpOversizeReply,
    /// Write a frame header and a short body, then close.
    UdpCloseAfterFirstFrame,
}

/// The protocol phase that a mock connection reached.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocksEvent {
    Greeting,
    Authenticated,
    Request,
}

/// One SOCKS request from the target device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocksRequest {
    pub command: u8,
    pub address: SocksAddress,
    pub port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SocksAddress {
    V4([u8; 4]),
    Domain(String),
    V6([u8; 16]),
}

/// What the mock source device observed on one connection. It holds no
/// secret. The fixed test token is checked, not stored.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SocksObservation {
    pub connection: usize,
    pub greeting_ok: bool,
    pub auth_ok: bool,
    pub auth_user_len: usize,
    pub auth_token_len: usize,
    pub request: Option<SocksRequest>,
    pub udp_in: Vec<Vec<u8>>,
    pub udp_out: Vec<Vec<u8>>,
    pub peer_closed_after_reply: bool,
}

/// The mock source device configuration. Debug output hides the token.
#[derive(Clone)]
pub struct SocksConfig {
    pub username: String,
    pub token: String,
    pub fault: SocksFault,
    pub reply: u8,
    pub payload: SocksPayload,
}

impl Default for SocksConfig {
    fn default() -> Self {
        Self {
            username: TEST_USER.into(),
            token: TEST_TOKEN.into(),
            fault: SocksFault::None,
            reply: 0,
            payload: SocksPayload::EchoTcp,
        }
    }
}

impl fmt::Debug for SocksConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SocksConfig")
            .field("username", &self.username)
            .field("token", &"[test fixture hidden]")
            .field("fault", &self.fault)
            .field("reply", &self.reply)
            .field("payload", &self.payload)
            .finish()
    }
}

/// The result of stopping the SOCKS emulator.
pub struct SocksReport {
    pub connections: usize,
    pub failures: Vec<String>,
    pub observations: Vec<SocksObservation>,
}

impl SocksReport {
    /// Panic when a script failed or a connection has no observation.
    pub fn assert_clean(&self) {
        MockReport {
            connections: self.connections,
            failures: self.failures.clone(),
        }
        .assert_clean();
        assert_eq!(
            self.connections,
            self.observations.len(),
            "each accepted connection must have one observation"
        );
    }
}

/// A loopback SOCKS5 source device.
pub struct MockSocksSource {
    server: MockServer,
    events: Arc<EventLog<SocksEvent>>,
    observations: Arc<Mutex<Vec<SocksObservation>>>,
}

impl MockSocksSource {
    pub fn start(config: SocksConfig) -> io::Result<Self> {
        Self::start_on((Ipv4Addr::LOCALHOST, 0).into(), config)
    }

    /// Start on a named address. The Linux tunnel test uses a veth address.
    pub fn start_on(address: SocketAddr, config: SocksConfig) -> io::Result<Self> {
        let events = Arc::new(EventLog::default());
        let observations = Arc::new(Mutex::new(Vec::new()));
        let handler_events = Arc::clone(&events);
        let handler_observations = Arc::clone(&observations);
        let server = MockServer::start_on(address, move |connection| {
            let mut observation = SocksObservation::default();
            let result = serve_socks(connection, &config, &mut observation, &handler_events);
            handler_observations.lock().unwrap().push(observation);
            result
        })?;
        Ok(Self {
            server,
            events,
            observations,
        })
    }

    pub fn address(&self) -> SocketAddr {
        self.server.address()
    }

    pub fn connections(&self) -> usize {
        self.server.connections()
    }

    /// Wait for one protocol phase.
    pub fn wait_for(&self, event: SocksEvent, limit: Duration) -> bool {
        self.events.wait_for(event, limit)
    }

    /// Stop the listener and every handler, then return the observations.
    pub fn stop(&mut self) -> SocksReport {
        let report = self.server.stop();
        SocksReport {
            connections: report.connections,
            failures: report.failures,
            observations: self.observations.lock().unwrap().clone(),
        }
    }
}

impl Drop for MockSocksSource {
    fn drop(&mut self) {
        let _ = self.server.stop();
    }
}

/// Run the source device side of one SOCKS5 connection.
pub fn serve_socks(
    connection: &mut MockConnection,
    config: &SocksConfig,
    observation: &mut SocksObservation,
    events: &EventLog<SocksEvent>,
) -> Result<(), String> {
    observation.connection = connection.index();

    let mut greeting = [0u8; 3];
    connection.read_exact(&mut greeting, "greeting")?;
    if greeting != [5, 1, 2] {
        return Err(connection.error("greeting", format!("unexpected bytes {greeting:?}")));
    }
    observation.greeting_ok = true;
    events.record(SocksEvent::Greeting);

    if config.fault == SocksFault::RejectMethod {
        connection.write_all(&[5, 0xff], "method rejection")?;
        return Ok(());
    }
    if config.fault == SocksFault::SilentAfterGreeting {
        connection.wait_stopped(Duration::from_secs(10));
        return Ok(());
    }
    if config.fault == SocksFault::CloseBeforeMethodReply {
        connection.shutdown();
        return Ok(());
    }
    if config.fault == SocksFault::PartialMethodReply {
        connection.write_all(&[5], "method reply prefix")?;
        connection.shutdown();
        return Ok(());
    }
    let fragmented = config.fault == SocksFault::FragmentedReplies;
    write_reply(connection, &[5, 2], fragmented, "method reply")?;

    let mut auth_header = [0u8; 2];
    if !connection.read_exact_allow_eof(&mut auth_header, "auth header")? {
        return Ok(());
    }
    if auth_header[0] != 1 {
        return Err(connection.error("auth header", "wrong auth version"));
    }
    let mut user = vec![0u8; auth_header[1] as usize];
    if !connection.read_exact_allow_eof(&mut user, "auth user")? {
        return Ok(());
    }
    let mut token_length = [0u8; 1];
    if !connection.read_exact_allow_eof(&mut token_length, "auth token length")? {
        return Ok(());
    }
    let mut token = vec![0u8; token_length[0] as usize];
    if !connection.read_exact_allow_eof(&mut token, "auth token")? {
        return Ok(());
    }
    observation.auth_user_len = user.len();
    observation.auth_token_len = token.len();
    observation.auth_ok = user == config.username.as_bytes() && token == config.token.as_bytes();
    events.record(SocksEvent::Authenticated);

    if config.fault == SocksFault::RejectCredentials || !observation.auth_ok {
        connection.write_all(&[1, 1], "auth rejection")?;
        return Ok(());
    }
    if config.fault == SocksFault::CloseBeforeAuthReply {
        connection.shutdown();
        return Ok(());
    }
    if config.fault == SocksFault::PartialAuthReply {
        connection.write_all(&[1], "auth reply prefix")?;
        connection.shutdown();
        return Ok(());
    }
    write_reply(connection, &[1, 0], fragmented, "auth reply")?;

    let mut header = [0u8; 4];
    if !connection.read_exact_allow_eof(&mut header, "request header")? {
        return Ok(());
    }
    if header[0] != 5 || header[2] != 0 {
        return Err(connection.error("request header", format!("invalid bytes {header:?}")));
    }
    let command = header[1];
    let Some(address) = read_address(connection, header[3])? else {
        return Ok(());
    };
    let mut port = [0u8; 2];
    if !connection.read_exact_allow_eof(&mut port, "request port")? {
        return Ok(());
    }
    observation.request = Some(SocksRequest {
        command,
        address,
        port: u16::from_be_bytes(port),
    });
    events.record(SocksEvent::Request);

    if config.fault == SocksFault::CloseBeforeConnectReply {
        connection.shutdown();
        return Ok(());
    }
    if config.fault == SocksFault::PartialConnectReply {
        connection.write_all(&[5, 0, 0], "connect reply prefix")?;
        connection.shutdown();
        return Ok(());
    }
    if config.reply != 0 {
        let mut reply = vec![5, config.reply, 0, 1, 0, 0, 0, 0];
        reply.extend_from_slice(&0u16.to_be_bytes());
        connection.write_all(&reply, "connect rejection")?;
        observation.peer_closed_after_reply =
            connection.wait_for_peer_close(Duration::from_secs(2))?;
        return Ok(());
    }
    let mut reply = vec![5, 0, 0, 1, 0, 0, 0, 0];
    reply.extend_from_slice(&0u16.to_be_bytes());
    write_reply(connection, &reply, fragmented, "connect reply")?;

    match command {
        1 => serve_tcp(connection, config.payload, observation),
        UDP_COMMAND => serve_udp(connection, config.payload, observation),
        _ => Err(connection.error("request", format!("unexpected command {command}"))),
    }
}

fn write_reply(
    connection: &mut MockConnection,
    bytes: &[u8],
    fragmented: bool,
    phase: &str,
) -> Result<(), String> {
    if !fragmented {
        return connection.write_all(bytes, phase);
    }
    for byte in bytes {
        connection.write_all(std::slice::from_ref(byte), phase)?;
        std::thread::sleep(Duration::from_millis(1));
    }
    Ok(())
}

fn read_address(
    connection: &mut MockConnection,
    address_type: u8,
) -> Result<Option<SocksAddress>, String> {
    match address_type {
        1 => {
            let mut octets = [0u8; 4];
            if !connection.read_exact_allow_eof(&mut octets, "IPv4 request address")? {
                return Ok(None);
            }
            Ok(Some(SocksAddress::V4(octets)))
        }
        3 => {
            let mut length = [0u8; 1];
            if !connection.read_exact_allow_eof(&mut length, "domain length")? {
                return Ok(None);
            }
            if length[0] == 0 {
                return Err(connection.error("domain length", "empty domain"));
            }
            let mut name = vec![0u8; length[0] as usize];
            if !connection.read_exact_allow_eof(&mut name, "domain name")? {
                return Ok(None);
            }
            let name = String::from_utf8(name)
                .map_err(|_| connection.error("domain name", "invalid UTF-8"))?;
            Ok(Some(SocksAddress::Domain(name)))
        }
        4 => {
            let mut octets = [0u8; 16];
            if !connection.read_exact_allow_eof(&mut octets, "IPv6 request address")? {
                return Ok(None);
            }
            Ok(Some(SocksAddress::V6(octets)))
        }
        other => Err(connection.error("request address type", format!("unexpected type {other}"))),
    }
}

fn serve_tcp(
    connection: &mut MockConnection,
    payload: SocksPayload,
    observation: &mut SocksObservation,
) -> Result<(), String> {
    match payload {
        SocksPayload::CloseTcp => {
            connection.shutdown();
            Ok(())
        }
        SocksPayload::EchoTcp => {
            let mut buffer = [0u8; 1024];
            loop {
                let read = connection.stream().read(&mut buffer);
                match read {
                    Ok(0) => {
                        observation.peer_closed_after_reply = true;
                        return Ok(());
                    }
                    Ok(count) => {
                        if let Err(error) = connection.stream().write_all(&buffer[..count]) {
                            return Err(connection.error("TCP echo", error));
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        if connection.stopped() {
                            return Ok(());
                        }
                        return Err(connection.error("TCP echo read", error));
                    }
                    Err(error) => return Err(connection.error("TCP echo read", error)),
                }
            }
        }
        _ => Err(connection.error("payload", "mode does not match TCP")),
    }
}

fn serve_udp(
    connection: &mut MockConnection,
    payload: SocksPayload,
    observation: &mut SocksObservation,
) -> Result<(), String> {
    match payload {
        SocksPayload::UdpEcho { frames } => {
            let mut echoed = 0;
            while echoed < frames {
                let Some(datagram) = connection.read_udp_frame("UDP datagram")? else {
                    return Ok(());
                };
                observation.udp_in.push(datagram.clone());
                connection.write_udp_frame(&datagram, "UDP echo")?;
                observation.udp_out.push(datagram);
                echoed += 1;
            }
            observation.peer_closed_after_reply =
                connection.wait_for_peer_close(Duration::from_secs(2))?;
            Ok(())
        }
        SocksPayload::UdpSilent => loop {
            match connection.read_udp_frame("UDP datagram")? {
                Some(datagram) => observation.udp_in.push(datagram),
                None => return Ok(()),
            }
        },
        SocksPayload::UdpOversizeReply => {
            let Some(datagram) = connection.read_udp_frame("UDP datagram")? else {
                return Ok(());
            };
            observation.udp_in.push(datagram);
            connection.write_all(&((MAX_DATAGRAM + 1) as u16).to_be_bytes(), "oversize frame")?;
            // The target device rejects the length before it reads the body.
            // A broken pipe here is the expected client action.
            let _ = connection.write_all(&vec![0u8; MAX_DATAGRAM + 1], "oversize frame body");
            Ok(())
        }
        SocksPayload::UdpCloseAfterFirstFrame => {
            let Some(datagram) = connection.read_udp_frame("UDP datagram")? else {
                return Ok(());
            };
            observation.udp_in.push(datagram);
            connection.write_all(&5u16.to_be_bytes(), "short frame length")?;
            connection.write_all(b"abc", "short frame body")?;
            connection.shutdown();
            Ok(())
        }
        _ => Err(connection.error("payload", "mode does not match UDP")),
    }
}

impl MockConnection {
    /// Read one length-prefixed datagram. Return None on a clean close before
    /// the length.
    pub fn read_udp_frame(&mut self, phase: &str) -> Result<Option<Vec<u8>>, String> {
        let mut header = [0u8; 2];
        if !self.read_exact_allow_eof(&mut header, phase)? {
            return Ok(None);
        }
        let length = u16::from_be_bytes(header) as usize;
        if length > MAX_DATAGRAM {
            return Err(self.error(phase, format!("client frame is too long: {length}")));
        }
        let mut payload = vec![0u8; length];
        if !self.read_exact_allow_eof(&mut payload, phase)? {
            return Err(self.error(phase, "peer closed inside a datagram"));
        }
        Ok(Some(payload))
    }

    pub fn write_udp_frame(&mut self, payload: &[u8], phase: &str) -> Result<(), String> {
        let length =
            u16::try_from(payload.len()).map_err(|_| self.error(phase, "datagram is too large"))?;
        self.write_all(&length.to_be_bytes(), phase)?;
        self.write_all(payload, phase)
    }
}
