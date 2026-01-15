//! QUIC-multiplexed relay server.
//!
//! Hosts establish QUIC connections. Player traffic is multiplexed using QUIC
//! datagrams with a 2-byte player ID prefix.

use anyhow::Result;
use dashmap::DashMap;
use quinn::Endpoint;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time;
use tracing::{info, warn};

use crate::io::{recv_json, send_json};
use crate::protocol::{ClientMessage, RelayMessage};
use crate::tls;

const SESSION_TIMEOUT: Duration = Duration::from_secs(60);

struct HostSession {
    host_ip: IpAddr,
    port: u16,
    last_seen: Instant,
    connection: quinn::Connection,
}

pub struct RelayServer {
    control_addr: SocketAddr,
    start_port: u16,
    end_port: u16,
    max_players: usize,
    password: Option<String>,
}

impl RelayServer {
    pub fn new(
        control_addr: SocketAddr,
        start_port: u16,
        end_port: u16,
        max_players: usize,
        password: Option<String>,
    ) -> Self {
        Self {
            control_addr,
            start_port,
            end_port,
            max_players,
            password,
        }
    }

    pub async fn run(&self) -> Result<()> {
        let server_config = tls::configure_server()?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_config)?,
        ));

        let transport = Arc::get_mut(&mut server_config.transport).unwrap();
        transport.max_idle_timeout(Some((SESSION_TIMEOUT * 2).try_into().unwrap()));
        transport.datagram_receive_buffer_size(Some(65536 * 100));
        transport.datagram_send_buffer_size(65536 * 100);

        let endpoint = Endpoint::server(server_config, self.control_addr)?;

        let control_addr = self.control_addr;
        info!("Relay server listening on {control_addr}");

        let host_sessions = Arc::new(DashMap::new());
        let port_cursor = Arc::new(RwLock::new(self.start_port));

        let sessions_clone = Arc::clone(&host_sessions);
        tokio::spawn(async move {
            cleanup_task(sessions_clone).await;
        });

        loop {
            let conn = match endpoint.accept().await {
                Some(conn) => conn,
                None => continue,
            };

            let host_sessions = Arc::clone(&host_sessions);
            let port_cursor = Arc::clone(&port_cursor);
            let max_players = self.max_players;
            let port_range = (self.start_port, self.end_port);
            let password = self.password.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_host_connection(
                    conn,
                    host_sessions,
                    port_cursor,
                    port_range,
                    max_players,
                    password,
                )
                .await
                {
                    warn!("Host connection error: {e}");
                }
            });
        }
    }
}

async fn cleanup_task(sessions: Arc<DashMap<String, HostSession>>) {
    let mut interval = time::interval(Duration::from_secs(10));

    loop {
        interval.tick().await;

        let now = Instant::now();
        let mut expired = Vec::new();

        for entry in sessions.iter() {
            if now.duration_since(entry.value().last_seen) > SESSION_TIMEOUT {
                expired.push((entry.key().clone(), entry.value().port));
            }
        }

        for (uuid, port) in expired {
            sessions.remove(&uuid);
            info!("Session timeout for {uuid}, released port {port}");
        }
    }
}

async fn handle_host_connection(
    incoming: quinn::Incoming,
    host_sessions: Arc<DashMap<String, HostSession>>,
    port_cursor: Arc<RwLock<u16>>,
    port_range: (u16, u16),
    max_players: usize,
    expected_password: Option<String>,
) -> Result<()> {
    let connection = incoming.await?;
    let remote = connection.remote_address();
    info!("Host connected from {remote}");

    let (mut send, mut recv) = connection.accept_bi().await?;
    let ClientMessage::SetupTunnel {
        host_uuid,
        password,
    } = recv_json::<ClientMessage>(&mut recv).await?;

    info!("Setup request for host {host_uuid}");

    if let Some(expected) = &expected_password {
        match password {
            Some(ref provided) if provided == expected => {
                info!("Password authenticated for {host_uuid}");
            }
            _ => {
                warn!("Authentication failed for {host_uuid}");
                send_json(
                    &mut send,
                    &RelayMessage::Error {
                        message: "Authentication failed".to_string(),
                    },
                )
                .await?;
                return Ok(());
            }
        }
    }

    if let Some(existing) = host_sessions.get(&host_uuid) {
        if existing.host_ip == remote.ip() {
            let old_port = existing.port;
            let old_connection = existing.connection.clone();
            drop(existing);
            host_sessions.remove(&host_uuid);
            info!("Invalidating old session from same IP, port {old_port}");
            old_connection.close(0u32.into(), b"reconnect");
        } else {
            warn!("Host UUID {host_uuid} already in use from different IP");
            send_json(
                &mut send,
                &RelayMessage::Error {
                    message: "Host UUID already in use".to_string(),
                },
            )
            .await?;
            return Ok(());
        }
    }

    let (allocated_port, forwarding_socket) = {
        let mut cursor = port_cursor.write().await;
        let (start, end) = port_range;
        let max_attempts = (end - start + 1) as usize;

        let mut result = None;
        for _ in 0..max_attempts {
            let candidate = *cursor;
            *cursor = if *cursor >= end { start } else { *cursor + 1 };

            match UdpSocket::bind(format!("0.0.0.0:{candidate}")).await {
                Ok(socket) => {
                    result = Some((candidate, socket));
                    break;
                }
                Err(_) => continue,
            }
        }

        let Some(result) = result else {
            warn!("No available ports in range");
            send_json(
                &mut send,
                &RelayMessage::Error {
                    message: "No available ports".to_string(),
                },
            )
            .await?;
            return Ok(());
        };

        result
    };

    host_sessions.insert(
        host_uuid.clone(),
        HostSession {
            host_ip: remote.ip(),
            port: allocated_port,
            last_seen: Instant::now(),
            connection: connection.clone(),
        },
    );

    send_json(
        &mut send,
        &RelayMessage::TunnelReady {
            port: allocated_port,
        },
    )
    .await?;

    info!("Allocated port {allocated_port} for {host_uuid}");

    run_quic_session(
        forwarding_socket,
        connection,
        host_sessions,
        host_uuid,
        max_players,
    )
    .await?;

    Ok(())
}

async fn run_quic_session(
    forwarding_socket: UdpSocket,
    connection: quinn::Connection,
    host_sessions: Arc<DashMap<String, HostSession>>,
    host_uuid: String,
    max_players: usize,
) -> Result<()> {
    let forwarding_socket = Arc::new(forwarding_socket);
    let port = forwarding_socket.local_addr()?.port();
    info!("Session started on port {port}");

    let players: Arc<DashMap<SocketAddr, u16>> = Arc::new(DashMap::new());
    let next_player_id = Arc::new(AtomicU16::new(0));

    let mut udp_buf = vec![0u8; 65536];

    loop {
        tokio::select! {
            stream_result = connection.accept_uni() => {
                match stream_result {
                    Ok(mut recv) => {
                        let sessions_clone = Arc::clone(&host_sessions);
                        let uuid_clone = host_uuid.clone();
                        tokio::spawn(async move {
                            let mut discard = [0u8; 1];
                            let _ = recv.read_exact(&mut discard).await;

                            if let Some(mut session) = sessions_clone.get_mut(&uuid_clone) {
                                session.last_seen = Instant::now();
                            }
                        });
                    }
                    Err(_) => return Ok(()),
                }
            }

            result = connection.read_datagram() => {
                let data = result?;

                if data.len() < 2 {
                    continue;
                }

                let player_id = u16::from_be_bytes([data[0], data[1]]);
                let packet = &data[2..];

                if let Some(entry) = players.iter().find(|e| *e.value() == player_id) {
                    forwarding_socket.send_to(packet, *entry.key()).await?;
                }
            }

            result = forwarding_socket.recv_from(&mut udp_buf) => {
                let (len, from) = result?;

                if let Some(mut session) = host_sessions.get_mut(&host_uuid) {
                    session.last_seen = Instant::now();
                }

                let player_id = if let Some(id) = players.get(&from) {
                    *id
                } else {
                    if players.len() >= max_players {
                        warn!("Max players reached, ignoring new connection from {from}");
                        continue;
                    }

                    let id = next_player_id.fetch_add(1, Ordering::Relaxed);
                    players.insert(from, id);
                    info!("Player connected from {from} (ID {id})");
                    id
                };

                let mut dgram = Vec::with_capacity(2 + len);
                dgram.extend_from_slice(&player_id.to_be_bytes());
                dgram.extend_from_slice(&udp_buf[..len]);

                if let Err(e) = connection.send_datagram(dgram.into()) {
                    warn!("Failed to send datagram to host: {e}");
                }
            }
        }
    }
}
