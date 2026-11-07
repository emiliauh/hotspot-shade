//! Test-only identities and pins.
//!
//! Every identity is generated in memory for one test run. No private key is
//! written to disk or committed. The certificate is self-signed and is trusted
//! only because the peer holds its pin.

use rcgen::{CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rustls::pki_types::CertificateDer;
use rustls::server::ParsedCertificate;
use sha2::{Digest, Sha256};

/// Return the DER SubjectPublicKeyInfo of a certificate.
///
/// This uses rustls's certificate parser instead of a hand-written DER walker.
/// A hand-written walker can overflow a length on a 32-bit target and panics on
/// attacker-controlled input. The parser is the same code rustls uses for the
/// handshake.
pub fn certificate_spki(cert_der: &[u8]) -> Option<Vec<u8>> {
    let cert = CertificateDer::from_slice(cert_der);
    ParsedCertificate::try_from(&cert)
        .ok()
        .map(|parsed| parsed.subject_public_key_info().as_ref().to_vec())
}

/// SHA-256 of a public value. A pin is not a secret.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Pin(pub [u8; 32]);

impl Pin {
    pub fn of_spki(spki_der: &[u8]) -> Self {
        Pin(Sha256::digest(spki_der).into())
    }

    pub fn of_certificate(cert_der: &[u8]) -> Self {
        Pin(Sha256::digest(cert_der).into())
    }

    pub fn hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}

impl std::fmt::Debug for Pin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Pins are public, so printing one is safe. It is useful in a failure
        // message because it names the identity that was presented.
        write!(f, "Pin({})", self.hex())
    }
}

/// One ephemeral certificate and its private key.
pub struct TestIdentity {
    pub cert_der: Vec<u8>,
    key_pkcs8: Vec<u8>,
    pub spki_der: Vec<u8>,
    pub spki_pin: Pin,
    pub cert_pin: Pin,
}

impl std::fmt::Debug for TestIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the private key. The certificate and pins are public.
        f.debug_struct("TestIdentity")
            .field("cert_pin", &self.cert_pin)
            .field("spki_pin", &self.spki_pin)
            .finish_non_exhaustive()
    }
}

impl TestIdentity {
    fn generate(common_name: &str, usage: ExtendedKeyUsagePurpose) -> Self {
        Self::generate_with(common_name, usage, &rcgen::PKCS_ECDSA_P256_SHA256)
    }

    fn generate_with(
        common_name: &str,
        usage: ExtendedKeyUsagePurpose,
        algorithm: &'static rcgen::SignatureAlgorithm,
    ) -> Self {
        let key_pair =
            KeyPair::generate_for(algorithm).expect("ring generated the requested ECDSA key pair");
        Self::from_key(key_pair, common_name, usage)
    }

    fn from_key(key_pair: KeyPair, common_name: &str, usage: ExtendedKeyUsagePurpose) -> Self {
        let mut params =
            CertificateParams::new(Vec::<String>::new()).expect("empty SAN list is valid");
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, common_name);
        params.distinguished_name = name;
        params.is_ca = IsCa::NoCa;
        params.use_authority_key_identifier_extension = false;
        params.extended_key_usages = vec![usage];

        let cert = params
            .self_signed(&key_pair)
            .expect("self-signed test certificate");
        let cert_der = cert.der().to_vec();
        let spki_der = key_pair.public_key_der();

        // The parser must find exactly the SPKI that rcgen produced. A
        // mismatch would silently pin the wrong bytes, so fail here.
        let extracted = certificate_spki(&cert_der).expect("certificate SPKI is present");
        assert_eq!(
            extracted, spki_der,
            "certificate parser must return the same SPKI as the key pair"
        );

        Self {
            spki_pin: Pin::of_spki(&spki_der),
            cert_pin: Pin::of_certificate(&cert_der),
            cert_der,
            key_pkcs8: key_pair.serialize_der(),
            spki_der,
        }
    }

    /// Issue a new certificate with the same key and a different subject. The
    /// SPKI pin must stay the same and the certificate pin must change.
    pub fn reissued(&self) -> Self {
        let key_pair = KeyPair::try_from(self.key_pkcs8.clone()).expect("stored PKCS#8 key parses");
        Self::from_key(
            key_pair,
            "hotspotshade tls spike reissued",
            ExtendedKeyUsagePurpose::ServerAuth,
        )
    }

    pub fn server() -> Self {
        Self::generate(
            "hotspotshade tls spike server",
            ExtendedKeyUsagePurpose::ServerAuth,
        )
    }

    pub fn client() -> Self {
        Self::generate(
            "hotspotshade tls spike client",
            ExtendedKeyUsagePurpose::ClientAuth,
        )
    }

    /// A server identity on ECDSA P-384. It is outside the spike signature
    /// policy, which advertises only P-256, and is used to show that a
    /// conforming peer cannot negotiate it.
    pub fn server_p384() -> Self {
        Self::generate_with(
            "hotspotshade tls spike server p384",
            ExtendedKeyUsagePurpose::ServerAuth,
            &rcgen::PKCS_ECDSA_P384_SHA384,
        )
    }

    /// A client identity on ECDSA P-384. It is outside the spike signature
    /// policy and is used to show that the server advertisement excludes it.
    pub fn client_p384() -> Self {
        Self::generate_with(
            "hotspotshade tls spike client p384",
            ExtendedKeyUsagePurpose::ClientAuth,
            &rcgen::PKCS_ECDSA_P384_SHA384,
        )
    }

    pub fn cert(&self) -> rustls::pki_types::CertificateDer<'static> {
        self.cert_der.clone().into()
    }

    pub fn key(&self) -> rustls::pki_types::PrivateKeyDer<'static> {
        rustls::pki_types::PrivatePkcs8KeyDer::from(self.key_pkcs8.clone()).into()
    }
}

impl Drop for TestIdentity {
    fn drop(&mut self) {
        // Best effort only. This clears the one PKCS#8 buffer this type owns.
        // Copies in rcgen, rustls, ring, and the allocator can remain, and the
        // compiler or allocator may reuse freed memory. The spike does not
        // claim memory zeroization.
        self.key_pkcs8.fill(0);
    }
}
