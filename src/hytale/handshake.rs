use std::sync::Arc;

use anyhow::{Result, anyhow};
use rustls::pki_types::CertificateDer;
use tokio::io::AsyncReadExt;
use tracing::{debug, trace};

use crate::auth::{
    CredentialStore, GameSession, JwtValidator, ServerIdentity, SessionClient,
    compute_certificate_fingerprint,
};

use super::packets::{AuthGrant, AuthToken, Connect, FRAME_HEADER_SIZE, Packet, ServerAuthToken};

/// Result of a successful player authentication.
pub struct HytaleAuthResult {
    pub player_uuid: uuid::Uuid,
    pub player_name: String,
    /// Player's access token, used when proxying to upstream servers.
    pub access_token: String,
    /// The original Connect packet, forwarded to upstream servers.
    pub connect_packet: Packet,
    /// Server's access token for this player session.
    pub server_access_token: String,
}

/// Handles the Hytale authentication handshake for incoming player connections.
///
/// Validates player identity tokens, exchanges authorization grants, and
/// produces access tokens. Create once at server startup and reuse for all
/// connections.
///
/// ```no_run
/// let authenticator = HytaleAuthenticator::with_identity(
///     ServerIdentity::default(),
///     credentials,
/// ).await?;
///
/// let result = authenticator.authenticate(&mut send, &mut recv, peer_certs).await?;
/// println!("Player {} authenticated", result.player_name);
/// ```
pub struct HytaleAuthenticator {
    server_identity: ServerIdentity,
    session_client: SessionClient,
    jwt_validator: JwtValidator,
    allow_skip_auth: bool,
    credentials: Arc<CredentialStore>,
}

impl HytaleAuthenticator {
    /// Creates an authenticator with explicit dependencies.
    pub fn new(
        server_identity: ServerIdentity,
        session_client: SessionClient,
        jwt_validator: JwtValidator,
        allow_skip_auth: bool,
        credentials: Arc<CredentialStore>,
    ) -> Self {
        Self {
            server_identity,
            session_client,
            jwt_validator,
            allow_skip_auth,
            credentials,
        }
    }

    /// Creates an authenticator with default clients, fetching JWKS automatically.
    pub async fn with_identity(
        server_identity: ServerIdentity,
        credentials: Arc<CredentialStore>,
    ) -> Result<Arc<Self>> {
        let session_client = SessionClient::new()?;
        let jwks = session_client.fetch_jwks().await?;
        let jwt_validator = JwtValidator::new(&server_identity, jwks);
        Ok(Arc::new(Self::new(
            server_identity,
            session_client,
            jwt_validator,
            false,
            credentials,
        )))
    }

    /// Runs the full authentication handshake with a connected player.
    /// Returns player info and tokens on success.
    #[tracing::instrument(skip_all, fields(uuid, username))]
    pub async fn authenticate(
        &self,
        send: &mut quinn::SendStream,
        recv: &mut quinn::RecvStream,
        peer_certs: Option<&[CertificateDer<'_>]>,
    ) -> Result<HytaleAuthResult> {
        let (connect_packet, connect) = self.receive_connect_packet(recv).await?;

        let span = tracing::Span::current();
        span.record("uuid", connect.uuid.to_string());
        span.record("username", &connect.username);

        trace!("player sent connect packet");

        let identity_claims = if let Some(ref token) = connect.identity_token {
            let claims = self.jwt_validator.validate_identity_token(token)?;
            trace!("identity token valid for: {:?}", claims.profile.username);
            Some(claims)
        } else if self.allow_skip_auth {
            return Ok(HytaleAuthResult {
                player_uuid: connect.uuid,
                player_name: connect.username,
                connect_packet,
                access_token: Default::default(),
                server_access_token: Default::default(),
            });
        } else {
            return Err(anyhow!("player connected without identity token"));
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
            .auth_grant(
                identity_token,
                &self.server_identity.audience,
                &session_token,
            )
            .await?;

        trace!("got authorization grant for player, sending AuthGrant");

        let server_identity_token = self.credentials.identity_token().await;
        let auth_grant_packet = AuthGrant::new(Some(auth_grant.clone()), server_identity_token);
        let packet_bytes = auth_grant_packet.encode_packet();
        send.write_all(&packet_bytes).await?;

        let auth_token = self.receive_auth_token_packet(recv).await?;

        let access_token = auth_token
            .access_token
            .ok_or_else(|| anyhow!("AuthToken missing access_token"))?;

        let server_auth_grant = auth_token
            .server_authorization_grant
            .ok_or_else(|| anyhow!("AuthToken missing server_authorization_grant"))?;

        let client_fingerprint = peer_certs.and_then(|c| {
            c.first()
                .map(|c| compute_certificate_fingerprint(c.as_ref()))
        });
        let access_claims = self
            .jwt_validator
            .validate_access_token(&access_token, client_fingerprint.as_deref())?;

        trace!("player authenticated successfully");

        let server_access_token = self
            .session_client
            .auth_token(
                &server_auth_grant,
                self.credentials.certificate_fingerprint(),
                &session_token,
            )
            .await
            .map_err(|e| anyhow!("Failed to exchange server auth grant: {e}"))?;

        let server_auth_token = ServerAuthToken::new(Some(server_access_token.clone()), None);
        let packet_bytes = server_auth_token.encode_packet();
        send.write_all(&packet_bytes).await?;

        let player_name = access_claims
            .username()
            .map(String::from)
            .or_else(|| identity_claims.and_then(|c| c.profile.username))
            .unwrap_or_else(|| connect.username.clone());

        Ok(HytaleAuthResult {
            player_uuid: connect.uuid,
            player_name,
            access_token,
            connect_packet,
            server_access_token,
        })
    }

    async fn ensure_game_session(&self) -> Result<()> {
        if self.credentials.game_session().await.is_some() {
            return Ok(());
        }

        let oauth = self.credentials.oauth_credentials().await;

        let response = self
            .session_client
            .create_game_session(&oauth.access_token, &oauth.profile_uuid)
            .await?;

        let session = GameSession {
            session_token: response.session_token.unwrap(),
            identity_token: response.identity_token.unwrap(),
            expires_at: response.expires_at.unwrap_or_default(),
        };

        trace!("created game session");

        self.credentials.set_game_session(session).await;

        Ok(())
    }

    async fn receive_connect_packet(
        &self,
        recv: &mut quinn::RecvStream,
    ) -> Result<(Packet, Connect)> {
        let packet = receive_packet(recv).await?;

        if packet.id() != Connect::PACKET_ID {
            return Err(anyhow!(
                "Expected Connect packet (ID {PACKET_ID}), got ID {id}",
                PACKET_ID = Connect::PACKET_ID,
                id = packet.id()
            ));
        }

        let connect = Connect::decode(&mut packet.payload())?;
        Ok((packet, connect))
    }

    async fn receive_auth_token_packet(&self, recv: &mut quinn::RecvStream) -> Result<AuthToken> {
        let packet = receive_packet(recv).await?;

        if packet.id() != AuthToken::PACKET_ID {
            return Err(anyhow!(
                "Expected AuthToken packet (ID {PACKET_ID}), got ID {id}",
                PACKET_ID = AuthToken::PACKET_ID,
                id = packet.id()
            ));
        }

        AuthToken::decode(&mut packet.payload())
    }
}

async fn receive_packet(recv: &mut quinn::RecvStream) -> Result<Packet> {
    use bytes::BytesMut;

    let mut buffer = BytesMut::with_capacity(65536);

    loop {
        if buffer.len() >= FRAME_HEADER_SIZE {
            let payload_len = u32::from_le_bytes(buffer[..4].try_into().unwrap()) as usize;
            let total_len = FRAME_HEADER_SIZE + payload_len;

            if buffer.len() >= total_len {
                let frame = buffer.split_to(total_len).freeze();
                let packet = Packet::from_frame(frame)?;
                debug!(
                    "[recv] Packet ID: {}, Payload: {} bytes",
                    packet.id(),
                    packet.len()
                );
                return Ok(packet);
            }
        }

        let n = recv.read_buf(&mut buffer).await?;
        if n == 0 {
            return Err(anyhow!("Connection closed while reading packet"));
        }
    }
}
