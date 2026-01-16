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
pub fn configure_server() -> Result<(Arc<rustls::ServerConfig>, CertificateDer<'static>)> {
    let (certs, key) = generate_self_signed_cert()?;
    let cert = certs.first().unwrap().clone();

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    server_config.alpn_protocols = vec![b"hytale/1".to_vec()];

    Ok((Arc::new(server_config), cert))
}
