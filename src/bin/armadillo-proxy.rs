use anyhow::anyhow;
use anyhow::{Context, Result};
use armadillo::{
    AuthGrant, AuthToken, CertSource, CredentialStore, HYTALE_ALPN, HytaleAuthResult,
    HytaleAuthenticator, PacketReader, ServerAuthToken, ServerIdentity, crypto, token_refresh_task,
};
use clap::Parser;
use quinn::SendStream;
use std::sync::Arc;
use std::{net::SocketAddr, path::PathBuf};
use tokio::net::lookup_host;
use tracing::{error, info, trace};

#[derive(Parser)]
#[command(name = "armadillo-proxy")]
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

fn load_server_credentials(
    path: PathBuf,
    machine_id: Option<String>,
    server_cert: &rustls::pki_types::CertificateDer<'_>,
) -> Result<Arc<CredentialStore>> {
    let auth_enc = std::fs::read(&path)?;
    let creds = crypto::auth_file::load_credentials_from_file(&auth_enc, machine_id.as_deref())?;
    Ok(Arc::new(CredentialStore::new(
        creds,
        path,
        machine_id,
        server_cert,
    )))
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

    let listen_addr: SocketAddr = cli.listen.parse()?;
    let upstream_addr = resolve_address(&cli.upstream).await?;

    let (endpoint, server_cert) =
        armadillo::make_server_endpoint(listen_addr, HYTALE_ALPN, CertSource::SelfSigned)?;

    let store = load_server_credentials(cli.auth, cli.machine_id, &server_cert)?;
    let oauth = store.oauth_credentials().await;
    info!(
        "Loaded server credentials for profile: {}",
        oauth.profile_uuid
    );
    info!("Token expires at: {}", oauth.expires_at);

    tokio::spawn(token_refresh_task(store.clone()));

    start_proxy(store, endpoint, upstream_addr).await
}

async fn start_proxy(
    credentials: Arc<CredentialStore>,
    endpoint: quinn::Endpoint,
    upstream_addr: SocketAddr,
) -> Result<()> {
    info!(
        "Proxy listening on: {}",
        endpoint
            .local_addr()
            .unwrap_or_else(|_| "unknown".parse().unwrap())
    );
    info!("Upstream server: {upstream_addr}");

    let server_identity = ServerIdentity::default();
    let authenticator =
        HytaleAuthenticator::with_identity(server_identity, credentials.clone()).await?;

    while let Some(incoming) = endpoint.accept().await {
        info!("Client connecting from: {}", incoming.remote_address());

        let auth = authenticator.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(incoming, &auth, upstream_addr).await {
                error!("Connection error: {e}");
            }
        });
    }

    Ok(())
}

#[tracing::instrument(skip_all, fields(peer_addr = %incoming.remote_address()))]
async fn handle_client(
    incoming: quinn::Incoming,
    authenticator: &HytaleAuthenticator,
    upstream_addr: SocketAddr,
) -> Result<()> {
    let mut client = armadillo::accept_client(incoming).await?;
    info!("Client connected: {}", client.peer_addr());

    if let Some(certs) = client.peer_certs() {
        info!("Client presented {} certificate(s)", certs.len());
    } else {
        info!("Client did not present any certificates");
    }

    let peer_certs = client.peer_certs();
    let peer_certs_ref = peer_certs.as_deref();

    let auth_result = authenticator
        .authenticate(&mut client.send, &mut client.recv, peer_certs_ref)
        .await?;

    info!(
        "Player authenticated: {} ({})",
        auth_result.player_name, auth_result.player_uuid
    );

    let mut server =
        armadillo::connect_upstream(upstream_addr, HYTALE_ALPN, CertSource::SelfSigned).await?;
    info!("Connected to upstream: {upstream_addr}");

    let client_rx = PacketReader::new(client.recv);
    let mut server_rx = PacketReader::new(server.recv);

    hytale_server_handshake(&mut server.send, &mut server_rx, &auth_result).await?;
    info!("Server handshake complete");

    relay_with_logging(client.send, client_rx, server.send, server_rx).await
}

async fn relay_with_logging(
    client_send: SendStream,
    client_recv: PacketReader,
    server_send: SendStream,
    server_recv: PacketReader,
) -> Result<()> {
    let c2s = relay_direction(client_recv, server_send, "client->server");
    let s2c = relay_direction(server_recv, client_send, "server->client");
    tokio::try_join!(c2s, s2c)?;
    Ok(())
}

async fn relay_direction(
    mut recv: PacketReader,
    mut send: SendStream,
    direction: &str,
) -> Result<()> {
    loop {
        match recv.read_packet().await {
            Ok(packet) => {
                tracing::debug!(
                    "[{direction}] packet_id={} payload_len={}",
                    packet.id(),
                    packet.len()
                );
                send.write_all(packet.frame()).await?;
            }
            Err(e) => {
                info!("[{direction}] Stream ended: {e}");
                break;
            }
        }
    }

    Ok(())
}

async fn hytale_server_handshake(
    send: &mut quinn::SendStream,
    recv: &mut PacketReader,
    auth_result: &HytaleAuthResult,
) -> Result<()> {
    send.write_all(auth_result.connect_packet.frame()).await?;

    let auth_grant = receive_auth_grant(recv).await?;
    trace!("received AuthGrant from server");

    let auth_token = AuthToken::new(
        Some(auth_result.access_token.clone()),
        auth_grant.authorization_grant.clone(),
    );
    let auth_token_bytes = auth_token.encode_packet();
    send.write_all(&auth_token_bytes).await?;

    let _server_auth_token = receive_server_auth_token(recv).await?;
    trace!("received ServerAuthToken from server");

    Ok(())
}

async fn receive_auth_grant(recv: &mut PacketReader) -> Result<AuthGrant> {
    let packet = recv.read_packet().await?;

    if packet.id() != AuthGrant::PACKET_ID {
        return Err(anyhow!(
            "Expected AuthGrant (ID {PACKET_ID}), got ID {id}",
            PACKET_ID = AuthGrant::PACKET_ID,
            id = packet.id()
        ));
    }

    AuthGrant::decode(&mut packet.payload())
}

async fn receive_server_auth_token(recv: &mut PacketReader) -> Result<ServerAuthToken> {
    let packet = recv.read_packet().await?;

    if packet.id() != ServerAuthToken::PACKET_ID {
        return Err(anyhow!(
            "Expected ServerAuthToken (ID {PACKET_ID}), got ID {id}",
            PACKET_ID = ServerAuthToken::PACKET_ID,
            id = packet.id()
        ));
    }

    ServerAuthToken::decode(&mut packet.payload())
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
