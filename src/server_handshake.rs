use anyhow::{Result, anyhow};
use tracing::{debug, info};

use crate::packets::{AuthGrant, AuthToken, Packet, PacketReader, ServerAuthToken, write_packet};

pub struct ServerHandshakeHandler;

impl ServerHandshakeHandler {
    pub async fn complete_handshake(
        connect_packet: &Packet,
        client_access_token: &str,
        server_recv: &mut quinn::RecvStream,
        server_send: &mut quinn::SendStream,
    ) -> Result<()> {
        let mut reader = PacketReader::new();

        let packet_bytes = write_packet(connect_packet);
        server_send.write_all(&packet_bytes).await?;
        debug!(
            "[proxy->server] Packet ID: {}, Payload: {} bytes",
            connect_packet.id,
            connect_packet.payload.len()
        );

        let auth_grant = Self::receive_auth_grant(&mut reader, server_recv).await?;
        debug!("Received AuthGrant from server");

        let auth_token = AuthToken::new(
            Some(client_access_token.to_string()),
            auth_grant.authorization_grant.clone(),
        );
        let auth_token_bytes = auth_token.encode_packet();
        debug!(
            "[proxy->server] Packet ID: {}, Payload: {} bytes",
            AuthToken::PACKET_ID,
            auth_token_bytes.len().saturating_sub(8)
        );
        server_send.write_all(&auth_token_bytes).await?;

        let _server_auth_token = Self::receive_server_auth_token(&mut reader, server_recv).await?;
        debug!("Received ServerAuthToken from server");

        info!("Server handshake complete");
        Ok(())
    }

    async fn receive_auth_grant(
        reader: &mut PacketReader,
        recv: &mut quinn::RecvStream,
    ) -> Result<AuthGrant> {
        let packet = Self::receive_packet(reader, recv).await?;

        if packet.id != AuthGrant::PACKET_ID {
            return Err(anyhow!(
                "Expected AuthGrant (ID {PACKET_ID}), got ID {id}",
                PACKET_ID = AuthGrant::PACKET_ID,
                id = packet.id
            ));
        }

        let mut payload = packet.payload;
        AuthGrant::decode(&mut payload)
    }

    async fn receive_server_auth_token(
        reader: &mut PacketReader,
        recv: &mut quinn::RecvStream,
    ) -> Result<ServerAuthToken> {
        let packet = Self::receive_packet(reader, recv).await?;

        if packet.id != ServerAuthToken::PACKET_ID {
            return Err(anyhow!(
                "Expected ServerAuthToken (ID {PACKET_ID}), got ID {id}",
                PACKET_ID = ServerAuthToken::PACKET_ID,
                id = packet.id
            ));
        }

        let mut payload = packet.payload;
        ServerAuthToken::decode(&mut payload)
    }

    async fn receive_packet(
        reader: &mut PacketReader,
        recv: &mut quinn::RecvStream,
    ) -> Result<crate::packets::Packet> {
        use tokio::io::AsyncReadExt;

        loop {
            match reader.try_parse_packet()? {
                Some(packet) => {
                    debug!(
                        "[server->proxy] Packet ID: {}, Payload: {} bytes",
                        packet.id,
                        packet.payload.len()
                    );
                    return Ok(packet);
                }
                None => {
                    let n = recv.read_buf(reader.buffer_mut()).await?;
                    if n == 0 {
                        return Err(anyhow!("Connection closed while reading packet"));
                    }
                }
            }
        }
    }
}
