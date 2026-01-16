//! Self-signed TLS certificates for QUIC

use anyhow::Result;
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;

/// Generates a self-signed certificate
pub fn generate_self_signed_cert() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>
{
    let params = CertificateParams::new(vec!["hytale-armadillo-relay".to_string()])?;
    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivatePkcs8KeyDer::from(key_pair.serialize_der());

    Ok((vec![cert_der], key_der.into()))
}

/// Creates server TLS config with self-signed cert
pub fn configure_server() -> Result<Arc<rustls::ServerConfig>> {
    let (certs, key) = generate_self_signed_cert()?;

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    server_config.alpn_protocols = vec![b"hq-29".to_vec()];

    Ok(Arc::new(server_config))
}

/// Creates client TLS config that accepts any certificate
pub fn configure_client() -> Arc<rustls::ClientConfig> {
    let mut client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    client_config.alpn_protocols = vec![b"hq-29".to_vec()];

    Arc::new(client_config)
}

/// Accepts all certificates without verification
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
