//! A hermetic source device pairing emulator.
//!
//! The emulator runs the source device side of protocol v1 on a loopback
//! listener. It uses the public pairing helpers and fixed public test keys.
//! It never stores a real identity or token. Fault scripts stop at one
//! bounded phase.

use super::{
    EventLog, MockConnection, MockReport, MockServer, TEST_HOST, TEST_PHONE_PORT, TEST_TOKEN,
};
use hotspotshade::pairing::{
    agree, commitment, decode_hello, decode_reveal, derive_keys, encode_challenge,
    encode_result_ok, encode_result_status, format_code, frame, sas_code, seal_credentials,
    transcript_hash, verify_proof, PhoneCredentials, PhoneStatus, MAX_FRAME,
};
use std::fmt;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use x25519_dalek::{PublicKey, StaticSecret};

/// The fault that one mock pairing connection emulates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingFault {
    None,
    /// Answer HELLO with a non-zero RESULT and no CHALLENGE.
    StatusBeforeChallenge(PhoneStatus),
    /// Read HELLO and never answer.
    SilentAfterHello,
    /// Close after HELLO.
    CloseAfterHello,
    /// Write a frame length larger than the protocol limit, then stop.
    OversizeFrame,
    /// Write a short prefix of a frame, then close.
    PartialFrame,
    /// Send a CHALLENGE that is one byte too short.
    ShortChallenge,
    /// Read REVEAL and never answer.
    SilentAfterReveal,
    /// Close after REVEAL.
    CloseAfterReveal,
    /// Send a short prefix of the RESULT frame, then close.
    PartialResult,
    /// Send a RESULT with one changed ciphertext byte.
    TamperedResult,
    /// Send a RESULT that names a host other than the connected address.
    WrongHost,
    /// Reject the pairing after a valid REVEAL.
    RejectProof,
}

/// The protocol phase that a mock pairing connection reached.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingEvent {
    Hello,
    ChallengeSent,
    RevealRead,
    ResultSent,
}

/// One pairing attempt as the mock source device saw it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PairingObservation {
    pub connection: usize,
    pub hello_received: bool,
    pub hello_flags: Option<u8>,
    pub proof_ok: bool,
    pub code: Option<String>,
}

/// The mock pairing source configuration. Debug output hides the test keys
/// and the test token.
#[derive(Clone)]
pub struct PairingConfig {
    pub credentials: PhoneCredentials,
    pub known: bool,
    pub fault: PairingFault,
    pub nonce: [u8; 12],
    pub ephemeral_secret: [u8; 32],
}

impl Default for PairingConfig {
    fn default() -> Self {
        Self {
            credentials: PhoneCredentials {
                host: TEST_HOST,
                port: TEST_PHONE_PORT,
                token: TEST_TOKEN.into(),
            },
            known: true,
            fault: PairingFault::None,
            nonce: [0x44; 12],
            ephemeral_secret: [0x33; 32],
        }
    }
}

impl fmt::Debug for PairingConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingConfig")
            .field("credentials", &self.credentials)
            .field("known", &self.known)
            .field("fault", &self.fault)
            .field("nonce", &self.nonce)
            .field("ephemeral_secret", &"[test fixture hidden]")
            .finish()
    }
}

/// The result of stopping the pairing emulator.
pub struct PairingReport {
    pub connections: usize,
    pub failures: Vec<String>,
    pub observations: Vec<PairingObservation>,
}

impl PairingReport {
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

/// A loopback pairing source device.
pub struct MockPairingSource {
    server: MockServer,
    events: Arc<EventLog<PairingEvent>>,
    observations: Arc<Mutex<Vec<PairingObservation>>>,
}

impl MockPairingSource {
    pub fn start(config: PairingConfig) -> io::Result<Self> {
        let events = Arc::new(EventLog::default());
        let observations = Arc::new(Mutex::new(Vec::new()));
        let handler_events = Arc::clone(&events);
        let handler_observations = Arc::clone(&observations);
        let server = MockServer::start(move |connection| {
            let mut observation = PairingObservation::default();
            let result = serve_pairing(connection, &config, &mut observation, &handler_events);
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
    pub fn wait_for(&self, event: PairingEvent, limit: Duration) -> bool {
        self.events.wait_for(event, limit)
    }

    /// Stop the listener and every handler, then return the observations.
    pub fn stop(&mut self) -> PairingReport {
        let report = self.server.stop();
        PairingReport {
            connections: report.connections,
            failures: report.failures,
            observations: self.observations.lock().unwrap().clone(),
        }
    }
}

impl Drop for MockPairingSource {
    fn drop(&mut self) {
        let _ = self.server.stop();
    }
}

/// Run the source device side of one pairing connection.
pub fn serve_pairing(
    connection: &mut MockConnection,
    config: &PairingConfig,
    observation: &mut PairingObservation,
    events: &EventLog<PairingEvent>,
) -> Result<(), String> {
    observation.connection = connection.index();

    let Some(hello) = connection.read_frame(MAX_FRAME, "pairing hello")? else {
        return Ok(());
    };
    let (l_s, commit) =
        decode_hello(&hello).map_err(|error| connection.error("pairing hello", error))?;
    observation.hello_received = true;
    observation.hello_flags = hello.get(66).copied();
    events.record(PairingEvent::Hello);

    match config.fault {
        PairingFault::SilentAfterHello => {
            connection.wait_stopped(Duration::from_secs(10));
            return Ok(());
        }
        PairingFault::CloseAfterHello => {
            connection.shutdown();
            return Ok(());
        }
        PairingFault::OversizeFrame => {
            let length = (MAX_FRAME + 1) as u16;
            connection.write_all(&length.to_be_bytes(), "oversize frame length")?;
            return Ok(());
        }
        PairingFault::PartialFrame => {
            connection.write_all(&32u16.to_be_bytes(), "partial frame length")?;
            connection.write_all(&[1, 2, 3, 4, 5], "partial frame body")?;
            connection.shutdown();
            return Ok(());
        }
        PairingFault::StatusBeforeChallenge(status) => {
            connection.write_frame(&encode_result_status(status), "pairing status")?;
            return Ok(());
        }
        _ => {}
    }

    let secret = StaticSecret::from(config.ephemeral_secret);
    let p_e = PublicKey::from(&secret).to_bytes();
    let mut challenge = encode_challenge(&p_e, config.known);
    if config.fault == PairingFault::ShortChallenge {
        challenge.pop();
    }
    connection.write_frame(&challenge, "pairing challenge")?;
    events.record(PairingEvent::ChallengeSent);

    let Some(reveal) = connection.read_frame(MAX_FRAME, "pairing reveal")? else {
        return Ok(());
    };
    let (l_e, proof) =
        decode_reveal(&reveal).map_err(|error| connection.error("pairing reveal", error))?;
    if commitment(&l_e, &l_s) != commit {
        connection.write_frame(
            &encode_result_status(PhoneStatus::Rejected),
            "pairing rejection",
        )?;
        return Ok(());
    }
    let ee = agree(&secret, &l_e).map_err(|error| connection.error("pairing key", error))?;
    let es = agree(&secret, &l_s).map_err(|error| connection.error("pairing key", error))?;
    let keys = derive_keys(&ee, &es, transcript_hash(&l_s, &l_e, &p_e));
    observation.proof_ok = verify_proof(&keys, &proof);
    observation.code = Some(format_code(&sas_code(&keys.sas)));
    events.record(PairingEvent::RevealRead);

    if !observation.proof_ok || config.fault == PairingFault::RejectProof {
        connection.write_frame(
            &encode_result_status(PhoneStatus::Rejected),
            "pairing rejection",
        )?;
        return Ok(());
    }

    match config.fault {
        PairingFault::SilentAfterReveal => {
            connection.wait_stopped(Duration::from_secs(10));
            return Ok(());
        }
        PairingFault::CloseAfterReveal => {
            connection.shutdown();
            return Ok(());
        }
        _ => {}
    }

    let credentials = if config.fault == PairingFault::WrongHost {
        PhoneCredentials {
            host: Ipv4Addr::new(192, 0, 2, 1),
            port: config.credentials.port,
            token: config.credentials.token.clone(),
        }
    } else {
        config.credentials.clone()
    };
    let mut ciphertext = seal_credentials(&keys, &config.nonce, &credentials)
        .map_err(|error| connection.error("pairing credentials", error))?;
    if config.fault == PairingFault::TamperedResult {
        ciphertext[0] ^= 1;
    }
    let result = encode_result_ok(&config.nonce, &ciphertext);

    if config.fault == PairingFault::PartialResult {
        let framed = frame(&result).map_err(|error| connection.error("pairing result", error))?;
        connection.write_all(&framed[..framed.len() / 2], "partial result")?;
        connection.shutdown();
        return Ok(());
    }

    connection.write_frame(&result, "pairing result")?;
    events.record(PairingEvent::ResultSent);
    Ok(())
}
