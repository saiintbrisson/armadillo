use anyhow::Result;
use rustls::pki_types::CertificateDer;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::crypto::{CertSource, generate_self_signed_cert};

/// An established QUIC connection to an upstream server with bidirectional streams.
pub struct UpstreamConnection {
    pub connection: quinn::Connection,
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
}

/// Connects to an upstream server over QUIC with client certificate authentication.
///
/// Server certificate verification is disabled, suitable for connecting to servers
/// with self-signed certificates. The client presents its own certificate for
/// mutual TLS when required by the server.
///
/// ```no_run
/// let upstream = connect_upstream(
///     "127.0.0.1:5521".parse()?,
///     HYTALE_ALPN,
///     CertSource::SelfSigned,
/// ).await?;
///
/// upstream.send.write_all(b"hello").await?;
/// ```
pub async fn connect_upstream(
    addr: SocketAddr,
    alpn: &[u8],
    cert_source: CertSource,
) -> Result<UpstreamConnection> {
    let (certs, key) = match cert_source {
        CertSource::SelfSigned => generate_self_signed_cert()?,
        CertSource::Memory { cert, key } => (vec![cert], key),
    };

    let mut client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_client_auth_cert(certs, key)?;

    client_config.alpn_protocols = vec![alpn.to_vec()];

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_config)?,
    ));

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    let conn = endpoint.connect(addr, "server")?.await?;
    let (send, recv) = conn.open_bi().await?;

    Ok(UpstreamConnection {
        connection: conn,
        send,
        recv,
    })
}

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
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
