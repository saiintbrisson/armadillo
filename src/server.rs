use anyhow::Result;
use quinn::Endpoint;
use rustls::pki_types::CertificateDer;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::crypto::{CertSource, make_server_tls_config};

/// Creates a QUIC server endpoint bound to the given address.
///
/// Returns the endpoint and the server's certificate (for fingerprint computation).
/// Use `accept_client` to handle incoming connections from the endpoint.
///
/// ```no_run
/// let (endpoint, cert) = make_server_endpoint(
///     "0.0.0.0:5520".parse()?,
///     HYTALE_ALPN,
///     CertSource::SelfSigned,
/// )?;
///
/// while let Some(incoming) = endpoint.accept().await {
///     let client = accept_client(incoming).await?;
/// }
/// ```
pub fn make_server_endpoint(
    bind_addr: SocketAddr,
    alpn: &[u8],
    cert_source: CertSource,
) -> Result<(Endpoint, CertificateDer<'static>)> {
    let (server_tls_config, cert) = make_server_tls_config(alpn, cert_source)?;

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_tls_config)?,
    ));

    let endpoint = Endpoint::server(server_config, bind_addr)?;
    Ok((endpoint, cert))
}

/// An accepted client connection with bidirectional streams ready for use.
pub struct ClientConnection {
    pub connection: quinn::Connection,
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
}

impl ClientConnection {
    /// Returns the client's remote address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    /// Returns the client's TLS certificates, if any were presented.
    pub fn peer_certs(&self) -> Option<Vec<CertificateDer<'static>>> {
        self.connection
            .peer_identity()
            .and_then(|certs| certs.downcast::<Vec<CertificateDer>>().ok())
            .map(|certs| (*certs).clone())
    }
}

/// Accepts an incoming QUIC connection and opens a bidirectional stream.
///
/// Completes the TLS handshake and waits for the client to open a stream.
/// The returned `ClientConnection` is ready for reading and writing.
///
/// ```no_run
/// while let Some(incoming) = endpoint.accept().await {
///     tokio::spawn(async move {
///         let client = accept_client(incoming).await?;
///         // client.send and client.recv are ready
///     });
/// }
/// ```
pub async fn accept_client(incoming: quinn::Incoming) -> Result<ClientConnection> {
    let conn = incoming.await?;
    let (send, recv) = conn.accept_bi().await?;
    Ok(ClientConnection {
        connection: conn,
        send,
        recv,
    })
}
