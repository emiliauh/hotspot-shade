//! Pinned TLS 1.3 configuration, ALPN policy, bounded handshake, and blocking
//! loopback helpers.
//!
//! The spike uses rustls for the handshake, record layer, key schedule, and
//! certificate message parsing. The custom pieces are the two trust decisions:
//! a server certificate verifier and a client certificate verifier. Both
//! compare a SHA-256 pin. rustls still checks the handshake signature with the
//! public key from the certificate, so a certificate without the matching
//! private key cannot authenticate even when the pin matches.
//!
//! Two policies live in this module, not in the test harness:
//!
//! - `accept_server` reads the ClientHello and rejects a client that offers no
//!   `ALPN` label. `handshake_server` and `handshake_client` then require the
//!   negotiated label to be exactly `ALPN`, so a peer that selects nothing is
//!   rejected on both sides. rustls itself only rejects a non-overlapping
//!   ALPN list; it accepts a client that sends no ALPN extension.
//! - `HandshakeDeadline` bounds the whole handshake, not one socket read. A
//!   peer that drips one byte at a time cannot extend it.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ResolvesClientCert, Resumption};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::Acceptor;
use rustls::sign::{CertifiedKey, Signer, SigningKey, SingleCertAndKey};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, DistinguishedName, Error,
    ProtocolVersion, ServerConfig, ServerConnection, SignatureScheme,
};

use crate::identity::{certificate_spki, Pin, TestIdentity};

/// A generic application protocol label. It deliberately does not carry the
/// product name or a version. ALPN metadata is still visible on the wire and a
/// fixed label remains a fingerprint; a production design must decide whether
/// that metadata is acceptable.
pub const ALPN: &[u8] = b"proxy";

/// The only signature scheme this spike accepts for a handshake signature.
///
/// The certificates are ECDSA P-256 and rcgen signs them with ECDSA-SHA256.
/// The verifiers advertise only this scheme, and they reject any other scheme
/// before calling the provider's signature check. Advertising the provider's
/// full list would claim support for algorithms this spike does not test and
/// does not issue.
pub const POLICY_SIGNATURE_SCHEMES: &[SignatureScheme] = &[SignatureScheme::ECDSA_NISTP256_SHA256];

/// Loopback test bound. A blocked test must fail, not hang a CI job.
pub const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Total budget for one handshake, measured from the moment the deadline is
/// created.
///
/// `IO_TIMEOUT` bounds a single socket read or write. A peer can keep resetting
/// that timer by dripping bytes, so the handshake also has one absolute
/// deadline. When the budget is gone, the handshake fails with
/// `io::ErrorKind::TimedOut` even if the last read made progress.
pub const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);

/// One absolute handshake deadline shared by the ClientHello read and every
/// later handshake read or write on the same connection.
#[derive(Debug, Clone)]
pub struct HandshakeDeadline {
    deadline: Instant,
}

impl HandshakeDeadline {
    /// Start a budget that begins now.
    pub fn new(budget: Duration) -> Self {
        Self {
            deadline: Instant::now() + budget,
        }
    }

    /// Use the spike's default handshake budget.
    pub fn default_policy() -> Self {
        Self::new(HANDSHAKE_DEADLINE)
    }

    /// Time left in the budget, or `TimedOut` when it is exhausted.
    ///
    /// The returned value is at least one millisecond so a socket timeout can
    /// never round down to zero, which some kernels read as "no timeout".
    pub fn remaining(&self) -> io::Result<Duration> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TLS handshake exceeded its total deadline",
            ));
        }
        Ok(remaining.max(Duration::from_millis(1)))
    }

    fn apply(&self, stream: &TcpStream) -> io::Result<()> {
        let remaining = self.remaining()?;
        stream.set_read_timeout(Some(remaining))?;
        stream.set_write_timeout(Some(remaining))
    }
}

/// True when an I/O error is a temporary stall that the handshake loop should
/// retry until the total deadline decides the outcome.
///
/// A socket read timeout is `WouldBlock` on Unix and `TimedOut` on Windows, so
/// both kinds are retryable here. The total deadline is the only time limit
/// that decides a failure.
fn retryable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

/// Require the negotiated ALPN label to be exactly the spike label.
///
/// This runs after the handshake on both sides. It is the second layer of the
/// policy: `accept_server` rejects a ClientHello whose offered list lacks the
/// label, and this check rejects a peer that did not select it.
pub fn require_negotiated_alpn(negotiated: Option<&[u8]>) -> io::Result<()> {
    match negotiated {
        Some(label) if label == ALPN => Ok(()),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("TLS handshake did not negotiate the required ALPN label: {other:?}"),
        )),
    }
}

/// Return the signature schemes the spike verifiers advertise.
pub fn policy_signature_schemes() -> Vec<SignatureScheme> {
    POLICY_SIGNATURE_SCHEMES.to_vec()
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn scheme_allowed(scheme: SignatureScheme) -> bool {
    POLICY_SIGNATURE_SCHEMES.contains(&scheme)
}

fn reject_disallowed_scheme(scheme: SignatureScheme) -> Result<(), Error> {
    if scheme_allowed(scheme) {
        Ok(())
    } else {
        Err(Error::General(format!(
            "signature scheme {scheme:?} is outside this spike's ECDSA P-256 policy"
        )))
    }
}

/// Which public value the client pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinKind {
    /// SHA-256 of the SubjectPublicKeyInfo. A renewed certificate for the same
    /// key keeps the same pin.
    Spki,
    /// SHA-256 of the whole leaf certificate DER. Any reissue changes the pin.
    Certificate,
}

fn pinned_value(cert_der: &[u8], kind: PinKind) -> Option<Pin> {
    match kind {
        PinKind::Spki => certificate_spki(cert_der).map(|spki| Pin::of_spki(&spki)),
        PinKind::Certificate => Some(Pin::of_certificate(cert_der)),
    }
}

/// Client side of the trust decision: accept the server only when the leaf
/// certificate matches the expected pin. The pin kind is SPKI or whole
/// certificate.
#[derive(Debug)]
pub struct PinnedServerVerifier {
    expected: Pin,
    kind: PinKind,
    algorithms: WebPkiSupportedAlgorithms,
    checks: Arc<AtomicUsize>,
}

impl PinnedServerVerifier {
    /// Number of times the pin check ran. A resumed session does not call it.
    pub fn checks(&self) -> Arc<AtomicUsize> {
        self.checks.clone()
    }
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.checks.fetch_add(1, Ordering::SeqCst);
        let Some(actual) = pinned_value(end_entity.as_ref(), self.kind) else {
            return Err(Error::General(
                "server certificate has no readable SPKI".into(),
            ));
        };
        if actual == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::General(format!(
                "server certificate pin mismatch: expected {}, got {}",
                self.expected.hex(),
                actual.hex()
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        reject_disallowed_scheme(dss.scheme)?;
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        reject_disallowed_scheme(dss.scheme)?;
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        policy_signature_schemes()
    }
}

/// Server side of the trust decision: accept a client only when the leaf
/// certificate SPKI hashes to the expected pin.
#[derive(Debug)]
pub struct PinnedClientVerifier {
    expected: Pin,
    algorithms: WebPkiSupportedAlgorithms,
    checks: Arc<AtomicUsize>,
}

impl PinnedClientVerifier {
    pub fn checks(&self) -> Arc<AtomicUsize> {
        self.checks.clone()
    }
}

impl ClientCertVerifier for PinnedClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // No CA hints. The client has exactly one pinned identity.
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        self.checks.fetch_add(1, Ordering::SeqCst);
        let Some(spki) = certificate_spki(end_entity.as_ref()) else {
            return Err(Error::General(
                "client certificate has no readable SPKI".into(),
            ));
        };
        let actual = Pin::of_spki(&spki);
        if actual == self.expected {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(Error::General(format!(
                "client certificate SPKI pin mismatch: expected {}, got {}",
                self.expected.hex(),
                actual.hex()
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        reject_disallowed_scheme(dss.scheme)?;
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        reject_disallowed_scheme(dss.scheme)?;
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        policy_signature_schemes()
    }
}

/// Build a client-certificate verifier with an observable pin-check counter.
pub fn pinned_client_verifier(expected: Pin) -> PinnedClientVerifier {
    PinnedClientVerifier {
        expected,
        algorithms: provider().signature_verification_algorithms,
        checks: Arc::new(AtomicUsize::new(0)),
    }
}

/// Build a server-certificate verifier with an observable pin-check counter.
pub fn pinned_server_verifier(expected: Pin, kind: PinKind) -> PinnedServerVerifier {
    PinnedServerVerifier {
        expected,
        kind,
        algorithms: provider().signature_verification_algorithms,
        checks: Arc::new(AtomicUsize::new(0)),
    }
}

/// A server configuration bound to one server identity and one pinned client.
pub struct ServerTls {
    pub config: Arc<ServerConfig>,
    pub client_cert_checks: Arc<AtomicUsize>,
}

/// A client configuration with an observable server-certificate pin counter.
pub struct ClientTls {
    pub config: Arc<ClientConfig>,
    pub server_cert_checks: Arc<AtomicUsize>,
}

fn certified_key_for(identity: &TestIdentity) -> Result<CertifiedKey, Error> {
    CertifiedKey::from_der(vec![identity.cert()], identity.key(), &provider())
}

/// Build a certificate/key pair without rustls's consistency check. Test-only:
/// a handshake with this pair must fail at CertificateVerify.
fn unchecked_certified_key(
    certificate: &TestIdentity,
    signing_key: &TestIdentity,
) -> Arc<CertifiedKey> {
    let signer = provider()
        .key_provider
        .load_private_key(signing_key.key())
        .expect("test signing key parses");
    Arc::new(CertifiedKey::new(vec![certificate.cert()], signer))
}

fn finish_server_config(
    certified: Arc<CertifiedKey>,
    trusted_client: Pin,
    tickets: usize,
    alpn: bool,
) -> ServerTls {
    let verifier = Arc::new(pinned_client_verifier(trusted_client));
    let client_cert_checks = verifier.checks();

    let mut config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 is present in the ring provider")
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));

    config.alpn_protocols = if alpn {
        vec![ALPN.to_vec()]
    } else {
        Vec::new()
    };
    // A TLS 1.3 ticket can let a later connection skip the certificate message
    // and both pin checks. The default spike config sends no tickets.
    config.send_tls13_tickets = tickets;
    ServerTls {
        config: Arc::new(config),
        client_cert_checks,
    }
}

/// Build a TLS 1.3-only server that asks every client for a certificate and
/// accepts only the pinned client SPKI. It sends no session tickets.
pub fn server_config(server: &TestIdentity, trusted_client: Pin) -> ServerTls {
    let certified = certified_key_for(server).expect("test server certificate and key match");
    finish_server_config(Arc::new(certified), trusted_client, 0, true)
}

/// Build a resumable server. Test-only: the spike policy disables resumption
/// so that every connection runs the full pin checks.
pub fn server_config_resumable(server: &TestIdentity, trusted_client: Pin) -> ServerTls {
    let certified = certified_key_for(server).expect("test server certificate and key match");
    finish_server_config(Arc::new(certified), trusted_client, 2, true)
}

/// Build a server that configures no ALPN. Test-only: it shows that a peer
/// which selects no application protocol is rejected by the client library.
pub fn server_config_without_alpn(server: &TestIdentity, trusted_client: Pin) -> ServerTls {
    let certified = certified_key_for(server).expect("test server certificate and key match");
    finish_server_config(Arc::new(certified), trusted_client, 0, false)
}

/// Build a server that presents `certificate` but signs with `signing_key`.
/// Test-only: this bypasses rustls's configuration-time key check so that the
/// test exercises CertificateVerify verification.
pub fn server_config_mismatched_signing_key(
    certificate: &TestIdentity,
    signing_key: &TestIdentity,
    trusted_client: Pin,
) -> ServerTls {
    finish_server_config(
        unchecked_certified_key(certificate, signing_key),
        trusted_client,
        0,
        true,
    )
}

/// Build a server that always signs with `scheme`, ignoring the client's
/// advertised signature schemes. Test-only: a conforming peer cannot produce a
/// scheme outside the policy when the policy advertisement is honest, so this
/// simulates one that ignores the advertisement. The signature body is a
/// placeholder; the verifier is expected to reject the scheme before it checks
/// any signature bytes.
pub fn server_config_with_forced_signature_scheme(
    server: &TestIdentity,
    scheme: SignatureScheme,
    trusted_client: Pin,
) -> ServerTls {
    let certified = Arc::new(CertifiedKey::new(
        vec![server.cert()],
        Arc::new(FixedSchemeSigningKey { scheme }),
    ));
    finish_server_config(certified, trusted_client, 0, true)
}

fn finish_client_config(
    resolver: Arc<dyn ResolvesClientCert>,
    trusted_server: Pin,
    kind: PinKind,
    alpn: Option<&[u8]>,
    resumption: bool,
) -> ClientTls {
    let verifier = Arc::new(pinned_server_verifier(trusted_server, kind));
    let server_cert_checks = verifier.checks();

    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 is present in the ring provider")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(resolver);

    config.alpn_protocols = alpn.map(|label| vec![label.to_vec()]).unwrap_or_default();
    if !resumption {
        // A resumed TLS 1.3 session can skip the certificate message. This
        // spike authenticates every connection with a pin, so it disables
        // resumption by default.
        config.resumption = Resumption::disabled();
    }
    ClientTls {
        config: Arc::new(config),
        server_cert_checks,
    }
}

fn normal_client_resolver(client: &TestIdentity) -> Result<Arc<dyn ResolvesClientCert>, Error> {
    let certified = certified_key_for(client)?;
    Ok(Arc::new(SingleCertAndKey::from(certified)))
}

fn client_config_with(
    client: &TestIdentity,
    trusted_server: Pin,
    kind: PinKind,
    alpn: Option<&[u8]>,
    resumption: bool,
) -> ClientTls {
    let resolver = normal_client_resolver(client).expect("test client certificate and key match");
    finish_client_config(resolver, trusted_server, kind, alpn, resumption)
}

/// Build a TLS 1.3-only client that accepts only the pinned server SPKI and
/// presents its own certificate for mutual authentication.
pub fn client_config(client: &TestIdentity, trusted_server: Pin) -> Arc<ClientConfig> {
    client_config_with(client, trusted_server, PinKind::Spki, Some(ALPN), false).config
}

/// Build a client with an observable server-certificate pin counter.
pub fn client_config_with_checks(client: &TestIdentity, trusted_server: Pin) -> ClientTls {
    client_config_with(client, trusted_server, PinKind::Spki, Some(ALPN), false)
}

/// Build a client that pins the whole server certificate instead of its SPKI.
pub fn client_config_cert_pin(
    client: &TestIdentity,
    trusted_server_cert: Pin,
) -> Arc<ClientConfig> {
    client_config_with(
        client,
        trusted_server_cert,
        PinKind::Certificate,
        Some(ALPN),
        false,
    )
    .config
}

/// Build a resumable client. Test-only: the spike policy disables resumption.
pub fn client_config_resumable(client: &TestIdentity, trusted_server: Pin) -> Arc<ClientConfig> {
    client_config_with(client, trusted_server, PinKind::Spki, Some(ALPN), true).config
}

/// Build a resumable client with an observable server-certificate pin counter.
pub fn client_config_resumable_with_checks(
    client: &TestIdentity,
    trusted_server: Pin,
) -> ClientTls {
    client_config_with(client, trusted_server, PinKind::Spki, Some(ALPN), true)
}

/// Build a client that offers no ALPN extension.
pub fn client_config_without_alpn(client: &TestIdentity, trusted_server: Pin) -> Arc<ClientConfig> {
    client_config_with(client, trusted_server, PinKind::Spki, None, false).config
}

/// Build a client that offers one ALPN label. Test-only.
pub fn client_config_with_alpn(
    client: &TestIdentity,
    trusted_server: Pin,
    label: &[u8],
) -> Arc<ClientConfig> {
    client_config_with(client, trusted_server, PinKind::Spki, Some(label), false).config
}

/// Try to build a client that presents `certificate` but signs with
/// `signing_key` through the usual configuration builder. rustls rejects this
/// before a connection exists because it checks that the private key matches
/// the certificate public key.
pub fn client_config_with_mismatched_key(
    certificate: &TestIdentity,
    signing_key: &TestIdentity,
    trusted_server: Pin,
) -> Result<Arc<ClientConfig>, rustls::Error> {
    let certified =
        CertifiedKey::from_der(vec![certificate.cert()], signing_key.key(), &provider())?;
    let resolver: Arc<dyn ResolvesClientCert> = Arc::new(SingleCertAndKey::from(certified));
    Ok(finish_client_config(resolver, trusted_server, PinKind::Spki, Some(ALPN), false).config)
}

/// Build a client that presents `certificate` but signs with `signing_key`.
/// Test-only: this bypasses rustls's configuration-time key check so that the
/// test exercises the server's CertificateVerify verification.
pub fn client_config_with_unchecked_signing_key(
    certificate: &TestIdentity,
    signing_key: &TestIdentity,
    trusted_server: Pin,
) -> Arc<ClientConfig> {
    let resolver: Arc<dyn ResolvesClientCert> = Arc::new(SingleCertAndKey::from(
        unchecked_certified_key(certificate, signing_key),
    ));
    finish_client_config(resolver, trusted_server, PinKind::Spki, Some(ALPN), false).config
}

/// Build a client that always signs with `scheme`, ignoring the server's
/// advertised signature schemes. Test-only: see
/// `server_config_with_forced_signature_scheme`. The signature body is a
/// placeholder; the verifier is expected to reject the scheme before it checks
/// any signature bytes.
pub fn client_config_with_forced_signature_scheme(
    client: &TestIdentity,
    scheme: SignatureScheme,
    trusted_server: Pin,
) -> Arc<ClientConfig> {
    let certified = Arc::new(CertifiedKey::new(
        vec![client.cert()],
        Arc::new(FixedSchemeSigningKey { scheme }),
    ));
    let resolver: Arc<dyn ResolvesClientCert> = Arc::new(SingleCertAndKey::from(certified));
    finish_client_config(resolver, trusted_server, PinKind::Spki, Some(ALPN), false).config
}

/// A signing key that reports one fixed scheme and ignores the peer's
/// advertised list. Test-only. A conforming peer cannot reach the disallowed
/// scheme check when both sides advertise the policy honestly, so this
/// simulates a peer that ignores the advertisement.
#[derive(Debug)]
struct FixedSchemeSigningKey {
    scheme: SignatureScheme,
}

impl SigningKey for FixedSchemeSigningKey {
    fn choose_scheme(&self, _offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        Some(Box::new(FixedSchemeSigner {
            scheme: self.scheme,
        }))
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        rustls::SignatureAlgorithm::ECDSA
    }
}

#[derive(Debug)]
struct FixedSchemeSigner {
    scheme: SignatureScheme,
}

impl Signer for FixedSchemeSigner {
    fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, Error> {
        // The policy check runs before any signature verification, so the body
        // is a placeholder. The test asserts the scheme rejection, not a
        // cryptographic result.
        Ok(vec![0u8; 8])
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

/// A client config that presents no certificate. It is used to show that this
/// server refuses an anonymous client before any application data.
pub fn client_config_without_cert(trusted_server: Pin) -> Arc<ClientConfig> {
    finish_client_config(
        Arc::new(NoClientCert),
        trusted_server,
        PinKind::Spki,
        Some(ALPN),
        false,
    )
    .config
}

#[derive(Debug)]
struct NoClientCert;

impl ResolvesClientCert for NoClientCert {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        None
    }

    fn has_certs(&self) -> bool {
        false
    }
}

pub fn tune(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))
}

pub fn new_server_connection(config: Arc<ServerConfig>) -> io::Result<ServerConnection> {
    ServerConnection::new(config).map_err(invalid_data)
}

pub fn new_client_connection(config: Arc<ClientConfig>) -> io::Result<ClientConnection> {
    // An IP address server name means rustls sends no SNI extension. The pin is
    // the trust decision, and a product-specific host name would be another
    // fingerprint.
    let name = ServerName::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST).into());
    ClientConnection::new(config, name).map_err(invalid_data)
}

fn invalid_data(error: rustls::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

/// Read the ClientHello, enforce the ALPN presence policy, and build a server
/// connection.
///
/// rustls rejects a client whose ALPN list does not overlap the server list
/// with a `no_application_protocol` alert. It accepts a client that sends no
/// ALPN extension at all, which would leave the connection without the spike
/// label. This function closes that gap before the handshake continues. A
/// caller that builds a `ServerConnection` directly is still caught by the
/// post-handshake check in `handshake_server`.
pub fn accept_server(
    stream: &mut TcpStream,
    config: Arc<ServerConfig>,
    deadline: &HandshakeDeadline,
) -> io::Result<ServerConnection> {
    let mut acceptor = Acceptor::default();
    loop {
        deadline.apply(stream)?;
        match acceptor.read_tls(stream) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "client closed before sending a ClientHello",
                ));
            }
            Ok(_) => {}
            Err(error) if retryable(&error) => {
                deadline.remaining()?;
                continue;
            }
            Err(error) => return Err(error),
        }

        match acceptor.accept() {
            Ok(Some(accepted)) => {
                let offers_label = accepted
                    .client_hello()
                    .alpn()
                    .map(|mut labels| labels.any(|label| label == ALPN))
                    .unwrap_or(false);
                if !offers_label {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "client did not offer the required ALPN label",
                    ));
                }
                return accepted
                    .into_connection(config)
                    .map_err(|(error, mut alert)| {
                        let _ = alert.write_all(stream);
                        invalid_data(error)
                    });
            }
            Ok(None) => {
                deadline.remaining()?;
            }
            Err((error, mut alert)) => {
                let _ = alert.write_all(stream);
                return Err(invalid_data(error));
            }
        }
    }
}

/// Drive one handshake until it completes or the total deadline expires, then
/// require the negotiated ALPN label.
fn drive_handshake(
    conn: &mut impl PlainConnection,
    io: &mut TcpStream,
    deadline: &HandshakeDeadline,
) -> io::Result<()> {
    loop {
        deadline.apply(io)?;
        let outcome = conn.complete_io_stream(io);
        let handshaking = conn.is_handshaking();
        match outcome {
            Ok((0, 0)) if handshaking => {
                // No progress and nothing queued. Do not spin; the deadline
                // decides the outcome on the next pass.
                deadline.remaining()?;
                thread::sleep(Duration::from_millis(1));
            }
            Ok(_) if handshaking => {
                deadline.remaining()?;
            }
            Ok(_) => break,
            Err(error) if retryable(&error) => {
                // A socket timeout is not the handshake deadline. The next
                // iteration uses a shorter timeout, and `remaining` fails once
                // the total budget is gone.
                deadline.remaining()?;
            }
            Err(error) => return Err(error),
        }
    }

    // The handshake is done. Restore the post-handshake socket bound.
    tune(io)?;
    require_negotiated_alpn(conn.alpn_protocol())
}

pub fn handshake_server(
    conn: &mut ServerConnection,
    io: &mut TcpStream,
    deadline: &HandshakeDeadline,
) -> io::Result<()> {
    drive_handshake(conn, io, deadline)
}

pub fn handshake_client(
    conn: &mut ClientConnection,
    io: &mut TcpStream,
    deadline: &HandshakeDeadline,
) -> io::Result<()> {
    drive_handshake(conn, io, deadline)
}

pub fn assert_tls13(version: Option<ProtocolVersion>) {
    assert_eq!(
        version,
        Some(ProtocolVersion::TLSv1_3),
        "spike must negotiate TLS 1.3"
    );
}

/// Write plaintext and flush all resulting TLS records.
///
/// rustls holds a bounded plaintext send buffer. Writing in bounded chunks and
/// flushing each one keeps `Writer::write` from returning `Ok(0)` on a large
/// application buffer. This is a blocking helper, not a production write
/// policy: it has no queued-output limit beyond the socket timeout.
pub fn write_plain(
    conn: &mut impl PlainConnection,
    io: &mut (impl Read + Write),
    data: &[u8],
) -> io::Result<()> {
    const CHUNK: usize = 16 * 1024;
    let mut rest = data;
    while !rest.is_empty() {
        let take = rest.len().min(CHUNK);
        conn.writer().write_all(&rest[..take])?;
        while conn.wants_write() {
            conn.write_tls(io)?;
        }
        rest = &rest[take..];
    }
    io.flush()
}

/// Read exactly `buf.len()` plaintext bytes.
pub fn read_exact_plain(
    conn: &mut impl PlainConnection,
    io: &mut (impl Read + Write),
    buf: &mut [u8],
) -> io::Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        match conn.reader().read(&mut buf[offset..]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => offset += n,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                conn.complete_io_for_read(io)?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Read one plaintext chunk. Returns 0 at a clean TLS close.
pub fn read_chunk_plain(
    conn: &mut impl PlainConnection,
    io: &mut (impl Read + Write),
    buf: &mut [u8],
) -> io::Result<usize> {
    loop {
        match conn.reader().read(buf) {
            Ok(n) => return Ok(n),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                conn.complete_io_for_read(io)?;
            }
            Err(error) => return Err(error),
        }
    }
}

/// The small part of `ClientConnection` / `ServerConnection` the helpers need.
pub trait PlainConnection {
    fn reader(&mut self) -> rustls::Reader<'_>;
    fn writer(&mut self) -> rustls::Writer<'_>;
    fn wants_write(&self) -> bool;
    fn write_tls(&mut self, io: &mut dyn Write) -> io::Result<usize>;
    fn complete_io_for_read<T: Read + Write>(&mut self, io: &mut T) -> io::Result<()>;
    fn complete_io_stream(&mut self, io: &mut TcpStream) -> io::Result<(usize, usize)>;
    fn is_handshaking(&self) -> bool;
    fn alpn_protocol(&self) -> Option<&[u8]>;
}

impl PlainConnection for ClientConnection {
    fn reader(&mut self) -> rustls::Reader<'_> {
        let common: &mut rustls::ConnectionCommon<rustls::client::ClientConnectionData> = self;
        common.reader()
    }
    fn writer(&mut self) -> rustls::Writer<'_> {
        let common: &mut rustls::ConnectionCommon<rustls::client::ClientConnectionData> = self;
        common.writer()
    }
    fn wants_write(&self) -> bool {
        let common: &rustls::ConnectionCommon<rustls::client::ClientConnectionData> = self;
        common.wants_write()
    }
    fn write_tls(&mut self, io: &mut dyn Write) -> io::Result<usize> {
        let common: &mut rustls::ConnectionCommon<rustls::client::ClientConnectionData> = self;
        common.write_tls(io)
    }
    fn complete_io_for_read<T: Read + Write>(&mut self, io: &mut T) -> io::Result<()> {
        let common: &mut rustls::ConnectionCommon<rustls::client::ClientConnectionData> = self;
        common.complete_io(io).map(|_| ())
    }
    fn complete_io_stream(&mut self, io: &mut TcpStream) -> io::Result<(usize, usize)> {
        let common: &mut rustls::ConnectionCommon<rustls::client::ClientConnectionData> = self;
        common.complete_io(io)
    }
    fn is_handshaking(&self) -> bool {
        let common: &rustls::CommonState = self;
        common.is_handshaking()
    }
    fn alpn_protocol(&self) -> Option<&[u8]> {
        let common: &rustls::CommonState = self;
        common.alpn_protocol()
    }
}

impl PlainConnection for ServerConnection {
    fn reader(&mut self) -> rustls::Reader<'_> {
        let common: &mut rustls::ConnectionCommon<rustls::server::ServerConnectionData> = self;
        common.reader()
    }
    fn writer(&mut self) -> rustls::Writer<'_> {
        let common: &mut rustls::ConnectionCommon<rustls::server::ServerConnectionData> = self;
        common.writer()
    }
    fn wants_write(&self) -> bool {
        let common: &rustls::ConnectionCommon<rustls::server::ServerConnectionData> = self;
        common.wants_write()
    }
    fn write_tls(&mut self, io: &mut dyn Write) -> io::Result<usize> {
        let common: &mut rustls::ConnectionCommon<rustls::server::ServerConnectionData> = self;
        common.write_tls(io)
    }
    fn complete_io_for_read<T: Read + Write>(&mut self, io: &mut T) -> io::Result<()> {
        let common: &mut rustls::ConnectionCommon<rustls::server::ServerConnectionData> = self;
        common.complete_io(io).map(|_| ())
    }
    fn complete_io_stream(&mut self, io: &mut TcpStream) -> io::Result<(usize, usize)> {
        let common: &mut rustls::ConnectionCommon<rustls::server::ServerConnectionData> = self;
        common.complete_io(io)
    }
    fn is_handshaking(&self) -> bool {
        let common: &rustls::CommonState = self;
        common.is_handshaking()
    }
    fn alpn_protocol(&self) -> Option<&[u8]> {
        let common: &rustls::CommonState = self;
        common.alpn_protocol()
    }
}

/// A `Write` wrapper that keeps a copy of the bytes that rustls wrote.
pub struct RecordingWriter<'a, W: Write> {
    inner: &'a mut W,
    pub recorded: Vec<u8>,
}

impl<'a, W: Write> RecordingWriter<'a, W> {
    pub fn new(inner: &'a mut W) -> Self {
        Self {
            inner,
            recorded: Vec::new(),
        }
    }
}

impl<W: Write> Write for RecordingWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.recorded.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Flush pending client TLS records and return the wire bytes.
pub fn flush_client_records(
    conn: &mut ClientConnection,
    io: &mut TcpStream,
) -> io::Result<Vec<u8>> {
    let mut recorder = RecordingWriter::new(io);
    while conn.wants_write() {
        conn.write_tls(&mut recorder)?;
    }
    recorder.flush()?;
    Ok(recorder.recorded)
}

/// Split a TLS record stream into complete records.
pub fn tls_records(wire: &[u8]) -> Vec<&[u8]> {
    let mut records = Vec::new();
    let mut rest = wire;
    while rest.len() >= 5 {
        let len = u16::from_be_bytes([rest[3], rest[4]]) as usize;
        if rest.len() < 5 + len {
            break;
        }
        records.push(&rest[..5 + len]);
        rest = &rest[5 + len..];
    }
    records
}

/// Return the first application-data record from a TLS record stream.
pub fn first_application_data_record(wire: &[u8]) -> Option<Vec<u8>> {
    tls_records(wire)
        .into_iter()
        .find(|record| record[0] == 23)
        .map(|record| record.to_vec())
}
