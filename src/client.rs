//! Tunnel client with QUIC multiplexing.
//!
//! Connects to relay via QUIC. Player traffic is multiplexed using QUIC datagrams
//! with a 2-byte player ID prefix.

use crate::io::{recv_json, send_json};
use crate::protocol::{ClientMessage, RelayMessage};
use crate::share_code::{CandidateType, ConnectionCandidate, ShareCodeData, encode_share_code};
use crate::tls;
use anyhow::Result;
use dashmap::DashMap;
use quinn::{Connection, Endpoint};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{info, warn};

pub struct TunnelClient {
    relay_addr: SocketAddr,
    local_server_addr: SocketAddr,
}

impl TunnelClient {
    pub async fn new(relay_addr: SocketAddr, local_server_addr: SocketAddr) -> Result<Self> {
        Ok(Self {
            relay_addr,
            local_server_addr,
        })
    }

    /// Establishes tunnel and generates modified share code
    pub async fn setup_tunnel(&self, share_data: ShareCodeData, password: Option<String>) -> Result<String> {
        let relay_addr = self.relay_addr;
        info!("Setting up tunnel to relay at {relay_addr}");

        let server_name = &share_data.server_name;
        let host_uuid = &share_data.host_uuid;
        info!("Server: {server_name} (UUID: {host_uuid})");

        let client_config = tls::configure_client();
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_config)?,
        )));

        let connection = endpoint.connect(self.relay_addr, "localhost")?.await?;

        info!("Connected to relay");

        let (mut send, mut recv) = connection.open_bi().await?;

        let msg = ClientMessage::SetupTunnel {
            host_uuid: share_data.host_uuid.clone(),
            password,
        };
        send_json(&mut send, &msg).await?;

        let response = recv_json::<RelayMessage>(&mut recv).await?;

        let port = match response {
            RelayMessage::TunnelReady { port } => {
                info!("Tunnel established on port {port}");
                port
            }
            RelayMessage::Error { message } => {
                anyhow::bail!("Relay error: {message}");
            }
        };

        let relay_ip = self.relay_addr.ip().to_string();
        let mut modified_share = share_data;
        modified_share.candidates = vec![ConnectionCandidate {
            type_: CandidateType::Relay,
            address: relay_ip,
            port,
            priority: 1000,
        }];

        let modified_code = encode_share_code(&modified_share)?;

        let local_server = self.local_server_addr;
        tokio::spawn(async move {
            if let Err(e) = run_tunnel_loop(connection, local_server).await {
                info!("Tunnel ended: {e}");
            }
        });

        Ok(modified_code)
    }

    /// Blocks forever (tunnel runs in background)
    pub async fn run_tunnel(&self) -> Result<()> {
        std::future::pending::<()>().await;
        Ok(())
    }
}

#[allow(clippy::map_entry)]
async fn run_tunnel_loop(connection: Connection, local_server_addr: SocketAddr) -> Result<()> {
    info!("Starting tunnel");

    let connection_clone = connection.clone();
    tokio::spawn(async move {
        keepalive_task(connection_clone).await;
    });

    let players = Arc::new(DashMap::new());

    loop {
        tokio::select! {
            result = connection.read_datagram() => {
                let data = result?;

                if data.len() < 2 {
                    continue;
                }

                let player_id = u16::from_be_bytes([data[0], data[1]]);
                let packet = &data[2..];

                if !players.contains_key(&player_id) {
                    info!("Player {} connected (ID {player_id})", players.len());

                    let local_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
                    local_socket.connect(local_server_addr).await?;

                    players.insert(player_id, Arc::clone(&local_socket));

                    let connection = connection.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_local_traffic(local_socket, connection, player_id).await {
                            info!("Player {player_id} local traffic ended: {e}");
                        }
                    });
                }

                if let Some(socket) = players.get(&player_id) {
                    socket.send(packet).await?;
                }
            }
        }
    }
}

async fn handle_local_traffic(
    local_socket: Arc<UdpSocket>,
    connection: Connection,
    player_id: u16,
) -> Result<()> {
    let mut buf = vec![0u8; 65536];

    loop {
        let len = local_socket.recv(&mut buf).await?;

        let mut dgram = Vec::with_capacity(2 + len);
        dgram.extend_from_slice(&player_id.to_be_bytes());
        dgram.extend_from_slice(&buf[..len]);

        if let Err(e) = connection.send_datagram(dgram.into()) {
            warn!("Failed to send datagram to relay: {e}");
        }
    }
}

async fn keepalive_task(connection: Connection) {
    let mut interval = tokio::time::interval(Duration::from_secs(15));

    loop {
        interval.tick().await;

        match connection.open_uni().await {
            Ok(mut send) => {
                let _ = send.write_all(&[0u8]).await;
                let _ = send.finish();
            }
            Err(_) => break,
        }
    }
}
