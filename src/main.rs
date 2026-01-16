mod auth;
mod crypto;
mod handshake;
mod packets;
mod server_handshake;
mod tls;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::Parser;
use quinn::Endpoint;
use std::sync::Arc;
use std::time::Duration;
use std::{net::SocketAddr, path::PathBuf};
use tokio::io::AsyncReadExt;
use tokio::net::lookup_host;
use tracing::{debug, error, info, warn};

use auth::CredentialStore;
use handshake::HandshakeHandler;
use packets::RawPacketReader;
use server_handshake::ServerHandshakeHandler;

#[derive(Parser)]
#[command(name = "armadillo")]
#[command(about = "QUIC proxy for Hytale with TLS termination")]
struct Cli {
    #[arg(short, long, default_value = "auth.enc")]
    auth: PathBuf,

    #[arg(short, long, default_value = "0.0.0.0:5520")]
    listen: String,

    #[arg(short, long, default_value = "127.0.0.1:5521")]
    upstream: String,

    #[arg(short, long, env = "ARMADILLO_MACHINE_ID")]
    machine_id: Option<String>,
}

fn load_server_credentials(path: PathBuf, machine_id: Option<String>) -> Result<CredentialStore> {
    let auth_enc = std::fs::read(&path)?;
    let creds = crypto::load_credentials_from_file(&auth_enc, machine_id.as_deref())?;
    Ok(CredentialStore::new(creds, path, machine_id))
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::DEBUG.into()),
        )
        .init();

    let cli = Cli::parse();

    let store = Arc::new(load_server_credentials(cli.auth, cli.machine_id)?);
    let oauth = store.oauth_credentials().await;
    info!(
        "Loaded server credentials for profile: {}",
        oauth.profile_uuid
    );
    info!("Token expires at: {}", oauth.expires_at);

    let listen_addr: SocketAddr = cli.listen.parse()?;
    let upstream_addr = resolve_address(&cli.upstream).await?;

    tokio::spawn(token_refresh_task(store.clone()));

    quinn_proxy(store, listen_addr, upstream_addr).await
}

const REFRESH_MARGIN: Duration = Duration::from_secs(5 * 60); // refresh 5 minutes before expiry

async fn token_refresh_task(store: Arc<CredentialStore>) {
    let client = match auth::SessionServiceClient::new("https://sessions.hytale.com") {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create session client for token refresh: {e}");
            return;
        }
    };

    loop {
        let oauth = store.oauth_credentials().await;

        let expires_at = match DateTime::parse_from_rfc3339(&oauth.expires_at) {
            Ok(dt) => dt.with_timezone(&Utc),
            Err(e) => {
                warn!("Failed to parse expires_at, refreshing now: {e}");
                Utc::now()
            }
        };

        let now = Utc::now();
        let refresh_at = expires_at - chrono::Duration::from_std(REFRESH_MARGIN).unwrap();
        let sleep_duration = if refresh_at > now {
            (refresh_at - now).to_std().unwrap_or(Duration::ZERO)
        } else {
            Duration::ZERO
        };

        if !sleep_duration.is_zero() {
            info!(
                "Token expires at {}, scheduling refresh in {}",
                expires_at.format("%Y-%m-%d %H:%M:%S UTC"),
                humanize_duration(sleep_duration)
            );
            tokio::time::sleep(sleep_duration).await;
        }

        info!("Refreshing OAuth token...");
        match client.refresh_oauth_token(&oauth.refresh_token).await {
            Ok(response) => {
                let new_expires = Utc::now() + chrono::Duration::seconds(response.expires_in);
                let updated = crypto::AuthCredentials {
                    access_token: response.access_token,
                    refresh_token: response.refresh_token,
                    expires_at: new_expires.to_rfc3339(),
                    profile_uuid: oauth.profile_uuid.clone(),
                };

                store.update_oauth_credentials(updated).await;

                if let Err(e) = store.persist_async().await {
                    error!("Failed to persist refreshed credentials: {e}");
                } else {
                    info!(
                        "OAuth token refreshed and saved, new expiry: {}",
                        new_expires.format("%Y-%m-%d %H:%M:%S UTC")
                    );
                }
            }
            Err(e) => {
                error!("Failed to refresh OAuth token: {e}");
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        }
    }
}

fn humanize_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs >= 3600 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{secs}s")
    }
}

async fn resolve_address(addr: &str) -> Result<SocketAddr> {
    let addr = if addr.contains(':') {
        addr.to_string()
    } else {
        format!("{addr}:5520")
    };

    if let Ok(socket_addr) = addr.parse() {
        return Ok(socket_addr);
    }

    lookup_host(&addr)
        .await
        .context("DNS lookup failed")?
        .next()
        .context("no addresses found")
}

async fn quinn_proxy(
    credentials: Arc<CredentialStore>,
    listen_addr: SocketAddr,
    upstream_addr: SocketAddr,
) -> Result<()> {
    let (server_config, server_cert) = tls::configure_server()?;

    let fingerprint = auth::compute_certificate_fingerprint(server_cert.as_ref());
    credentials.set_certificate_fingerprint(fingerprint).await;

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_config)?,
    ));

    let endpoint = Endpoint::server(server_config, listen_addr)?;

    info!("QUIC Proxy listening on: {listen_addr}");
    info!("Upstream server: {upstream_addr}");

    while let Some(incoming) = endpoint.accept().await {
        info!("Client connecting from: {}", incoming.remote_address());

        let creds = credentials.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(client_conn) => {
                    info!("Client connected: {}", client_conn.remote_address());

                    let client_certs = client_conn
                        .peer_identity()
                        .and_then(|certs| {
                            certs
                                .downcast::<Vec<rustls::pki_types::CertificateDer>>()
                                .ok()
                        })
                        .map(|certs| (*certs).clone());

                    if let Some(certs) = &client_certs {
                        info!("Client presented {} certificate(s)", certs.len());
                    } else {
                        info!("Client did not present any certificates");
                    }

                    match connect_to_upstream(upstream_addr).await {
                        Ok(server_conn) => {
                            info!("Connected to upstream: {upstream_addr}");
                            handle_proxy_connection(client_conn, server_conn, creds, client_certs)
                                .await;
                        }
                        Err(e) => {
                            error!("Failed to connect to upstream: {e}");
                        }
                    }
                }
                Err(e) => {
                    error!("Client connection failed: {e}");
                }
            }
        });
    }

    Ok(())
}

#[tracing::instrument]
async fn connect_to_upstream(addr: SocketAddr) -> Result<quinn::Connection> {
    let (certs, key) = tls::generate_self_signed_cert()?;

    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_client_auth_cert(certs, key)?;

    client_crypto.alpn_protocols = vec![b"hytale/1".to_vec()];

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
    ));

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    let conn = endpoint.connect(addr, "localhost")?.await?;
    Ok(conn)
}

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

async fn handle_proxy_connection(
    client_conn: quinn::Connection,
    server_conn: quinn::Connection,
    credentials: Arc<CredentialStore>,
    client_certs: Option<Vec<rustls::pki_types::CertificateDer<'static>>>,
) {
    let (mut client_send, mut client_recv) = match client_conn.accept_bi().await {
        Ok(stream) => stream,
        Err(e) => {
            error!("Failed to accept client stream: {e}");
            return;
        }
    };

    let handshake = match HandshakeHandler::new(credentials) {
        Ok(h) => h,
        Err(e) => {
            error!("Failed to create handshake handler: {e}");
            return;
        }
    };

    let client_cert_der = client_certs
        .as_ref()
        .and_then(|certs| certs.first())
        .map(|cert| cert.as_ref());

    let (session, raw_connect_packet, client_access_token) = match handshake
        .authenticate_player(&mut client_recv, &mut client_send, client_cert_der)
        .await
    {
        Ok(result) => result,
        Err(e) => {
            error!("Authentication failed: {e}");
            return;
        }
    };

    info!(
        "Player authenticated: {} ({})",
        session.username, session.uuid
    );

    let (mut server_send, mut server_recv) = match server_conn.open_bi().await {
        Ok(stream) => stream,
        Err(e) => {
            error!("Failed to open server stream: {e}");
            return;
        }
    };

    if let Err(e) = ServerHandshakeHandler::complete_handshake(
        &raw_connect_packet,
        &client_access_token,
        &mut server_recv,
        &mut server_send,
    )
    .await
    {
        error!("Server handshake failed: {e}");
        return;
    }

    info!("Server handshake complete");

    tokio::spawn(relay_stream(client_recv, server_send, "client->server"));
    tokio::spawn(relay_stream(server_recv, client_send, "server->client"));
}

#[tracing::instrument(skip_all)]
async fn relay_stream(mut recv: quinn::RecvStream, mut send: quinn::SendStream, direction: &str) {
    let mut reader = RawPacketReader::new();

    loop {
        match recv.read_buf(reader.buffer_mut()).await {
            Ok(0) => {
                info!("[{direction}] Stream closed");
                break;
            }
            Ok(_) => loop {
                match reader.try_read_packet() {
                    Ok(Some(packet)) => {
                        debug!(
                            "[{direction}] packet_id={} payload_len={}",
                            packet.id, packet.payload_len
                        );

                        if let Err(e) = send.write_all(&packet.bytes).await {
                            error!("[{direction}] Write error: {e}");
                            return;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        error!("[{direction}] Packet parse error: {e}");
                        return;
                    }
                }
            },
            Err(e) => {
                info!("[{direction}] Stream ended: {e}");
                break;
            }
        }
    }

    let _ = send.finish();
}
