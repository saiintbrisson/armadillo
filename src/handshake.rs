use anyhow::{Result, anyhow};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tracing::{debug, info, warn};

use crate::auth::{
    CredentialStore, GameSession, JwtValidator, SessionServiceClient,
    compute_certificate_fingerprint,
};
use crate::packets::{AuthGrant, AuthToken, ClientType, Connect, PacketReader, ServerAuthToken};

const SESSION_SERVICE_URL: &str = "https://sessions.hytale.com";

#[allow(dead_code)]
pub struct ServerIdentity {
    pub server_id: String,
    pub audience: String,
}

impl Default for ServerIdentity {
    fn default() -> Self {
        Self {
            server_id: "armadillo-proxy".to_string(),
            audience: "hytale:server:armadillo-proxy".to_string(),
        }
    }
}

pub struct HandshakeHandler {
    jwt_validator: JwtValidator,
    session_client: SessionServiceClient,
    credentials: Arc<CredentialStore>,
    server_identity: ServerIdentity,
}

impl HandshakeHandler {
    pub fn new(credentials: Arc<CredentialStore>) -> Result<Self> {
        let server_identity = ServerIdentity::default();

        Ok(Self {
            jwt_validator: JwtValidator::new(SESSION_SERVICE_URL, &server_identity.audience),
            session_client: SessionServiceClient::new(SESSION_SERVICE_URL)?,
            credentials,
            server_identity,
        })
    }

    pub async fn authenticate_player(
        &self,
        recv: &mut quinn::RecvStream,
        send: &mut quinn::SendStream,
        client_cert_der: Option<&[u8]>,
    ) -> Result<(PlayerSession, crate::packets::Packet, String)> {
        let mut reader = PacketReader::new();

        let (connect_packet, connect) = self.receive_connect_packet(&mut reader, recv).await?;
        info!(
            "Player connecting: {} (uuid: {})",
            connect.username, connect.uuid
        );

        let identity_claims = if let Some(ref token) = connect.identity_token {
            let claims = self.jwt_validator.validate_identity_token(token).await?;
            info!(
                "Identity token valid for: {:?}",
                claims.username().unwrap_or(&connect.username)
            );
            Some(claims)
        } else {
            warn!("Player connected without identity token");
            None
        };

        self.ensure_game_session().await?;

        let session_token = self
            .credentials
            .session_token()
            .await
            .ok_or_else(|| anyhow!("No session token available"))?;

        let identity_token = connect
            .identity_token
            .as_ref()
            .ok_or_else(|| anyhow!("Player must provide identity token"))?;

        let auth_grant = self
            .session_client
            .request_authorization_grant(
                identity_token,
                &self.server_identity.audience,
                &session_token,
            )
            .await?;

        info!("Got authorization grant for player");

        let server_identity_token = self.credentials.identity_token().await;

        let auth_grant_packet = AuthGrant::new(Some(auth_grant.clone()), server_identity_token);
        let packet_bytes = auth_grant_packet.encode_packet();
        debug!(
            "[proxy->client] Packet ID: {}, Payload: {} bytes",
            AuthGrant::PACKET_ID,
            packet_bytes.len().saturating_sub(8)
        );
        send.write_all(&packet_bytes).await?;

        let auth_token = self.receive_auth_token_packet(&mut reader, recv).await?;

        let access_token = auth_token
            .access_token
            .ok_or_else(|| anyhow!("AuthToken missing access_token"))?;

        let client_fingerprint = client_cert_der.map(compute_certificate_fingerprint);
        let access_claims = self
            .jwt_validator
            .validate_access_token(&access_token, client_fingerprint.as_deref())
            .await?;

        info!(
            "Player {} authenticated successfully",
            access_claims.username().unwrap_or(&connect.username)
        );

        let mut server_access_token_result = None;
        if let Some(ref server_grant) = auth_token.server_authorization_grant
            && let Some(fp) = self.credentials.certificate_fingerprint().await
        {
            match self
                .session_client
                .exchange_auth_grant(server_grant, &fp, &session_token)
                .await
            {
                Ok(token) => {
                    debug!("Exchanged server auth grant");
                    server_access_token_result = Some(token);
                }
                Err(e) => {
                    warn!("Failed to exchange server auth grant: {e}");
                }
            }
        }

        let server_auth_token = ServerAuthToken::new(server_access_token_result, None);
        let packet_bytes = server_auth_token.encode_packet();
        debug!(
            "[proxy->client] Packet ID: {}, Payload: {} bytes",
            ServerAuthToken::PACKET_ID,
            packet_bytes.len().saturating_sub(8)
        );
        send.write_all(&packet_bytes).await?;

        let session = PlayerSession {
            username: access_claims
                .username()
                .map(String::from)
                .or_else(|| identity_claims.and_then(|c| c.username().map(String::from)))
                .unwrap_or_else(|| connect.username.clone()),
            uuid: connect.uuid,
            client_type: connect.client_type,
        };

        Ok((session, connect_packet, access_token))
    }

    #[tracing::instrument(skip_all)]
    async fn ensure_game_session(&self) -> Result<()> {
        if self.credentials.game_session().await.is_some() {
            return Ok(());
        }

        let mut oauth = self.credentials.oauth_credentials().await;

        let result = self
            .session_client
            .create_game_session(&oauth.access_token, &oauth.profile_uuid)
            .await;

        let response = match result {
            Ok(resp) => resp,
            Err(e) => {
                let msg = e.to_string();
                if !msg.contains("403") && !msg.contains("invalid token") {
                    return Err(e);
                }

                info!("OAuth token expired, refreshing");
                let fresh = self
                    .session_client
                    .refresh_oauth_token(&oauth.refresh_token)
                    .await?;

                oauth.access_token = fresh.access_token;
                oauth.refresh_token = fresh.refresh_token;
                oauth.expires_at =
                    (chrono::Utc::now() + chrono::Duration::seconds(fresh.expires_in)).to_rfc3339();
                self.credentials
                    .update_oauth_credentials(oauth.clone())
                    .await;

                if let Err(e) = self.credentials.persist_async().await {
                    warn!("Failed to persist refreshed credentials: {e}");
                }

                info!("OAuth token refreshed");
                self.session_client
                    .create_game_session(&oauth.access_token, &oauth.profile_uuid)
                    .await?
            }
        };

        let session = GameSession {
            session_token: response.session_token.unwrap(),
            identity_token: response.identity_token.unwrap(),
            expires_at: response.expires_at.unwrap_or_default(),
        };

        info!("Created game session for proxy");
        self.credentials.set_game_session(session).await;

        Ok(())
    }

    async fn receive_connect_packet(
        &self,
        reader: &mut PacketReader,
        recv: &mut quinn::RecvStream,
    ) -> Result<(crate::packets::Packet, Connect)> {
        let packet = self.receive_packet(reader, recv).await?;

        if packet.id != Connect::PACKET_ID {
            return Err(anyhow!(
                "Expected Connect packet (ID {PACKET_ID}), got ID {id}",
                PACKET_ID = Connect::PACKET_ID,
                id = packet.id
            ));
        }

        let connect = Connect::decode(packet.payload.clone())?;
        Ok((packet, connect))
    }

    async fn receive_auth_token_packet(
        &self,
        reader: &mut PacketReader,
        recv: &mut quinn::RecvStream,
    ) -> Result<AuthToken> {
        let packet = self.receive_packet(reader, recv).await?;

        if packet.id != AuthToken::PACKET_ID {
            return Err(anyhow!(
                "Expected AuthToken packet (ID {PACKET_ID}), got ID {id}",
                PACKET_ID = AuthToken::PACKET_ID,
                id = packet.id
            ));
        }

        let mut payload = packet.payload;
        AuthToken::decode(&mut payload)
    }

    async fn receive_packet(
        &self,
        reader: &mut PacketReader,
        recv: &mut quinn::RecvStream,
    ) -> Result<crate::packets::Packet> {
        loop {
            match reader.try_parse_packet()? {
                Some(packet) => {
                    debug!(
                        "[client->proxy] Packet ID: {}, Payload: {} bytes",
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

#[allow(dead_code)]
#[derive(Debug)]
pub struct PlayerSession {
    pub username: String,
    pub uuid: uuid::Uuid,
    pub client_type: ClientType,
}
