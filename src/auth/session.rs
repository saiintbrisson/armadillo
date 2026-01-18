use anyhow::{Result, anyhow};
use reqwest::Client;
use rustls::pki_types::CertificateDer;
use serde::Deserialize;
use std::path::PathBuf;
use tokio::sync::RwLock;

use super::compute_certificate_fingerprint;
use crate::crypto::auth_file::{self, AuthCredentials};

pub const SESSION_SERVICE_URL: &str = "https://sessions.hytale.com";

#[derive(Debug, Deserialize)]
pub struct GameSessionResponse {
    #[serde(rename = "sessionToken")]
    pub session_token: Option<String>,
    #[serde(rename = "identityToken")]
    pub identity_token: Option<String>,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuthGrantResponse {
    #[serde(rename = "authorizationGrant")]
    pub authorization_grant: String,
}

#[derive(Debug, Deserialize)]
pub struct AccessTokenResponse {
    #[serde(rename = "accessToken")]
    pub access_token: String,
}

#[derive(Debug, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<JwkKey>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwkKey {
    pub kty: String,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(rename = "use", default)]
    pub key_use: Option<String>,
    pub kid: Option<String>,
    pub crv: Option<String>,
    pub x: Option<String>,
    #[serde(default)]
    pub y: Option<String>,
}

/// HTTP client for Hytale's session service at `https://sessions.hytale.com`.
///
/// Handles server-side authentication flows: creating game sessions, requesting
/// authorization grants for player joins, and exchanging grants for access tokens.
/// Also provides JWKS fetching for JWT signature verification.
///
/// ```ignore
/// let client = SessionClient::new()?;
/// let jwks = client.fetch_jwks().await?;
/// let session = client.create_game_session(&oauth_token, &profile_uuid).await?;
/// ```
pub struct SessionClient {
    client: Client,
    base_url: String,
}

impl SessionClient {
    /// Creates a client pointing to the production session service.
    pub fn new() -> Result<Self> {
        Self::with_base_url(SESSION_SERVICE_URL)
    }

    /// Creates a client with a custom base URL, useful for testing or staging environments.
    pub fn with_base_url(url: &str) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        let base_url = url.strip_suffix('/').unwrap_or(url).to_string();

        Ok(Self { client, base_url })
    }

    /// Fetches the JSON Web Key Set used to verify JWT signatures.
    /// Call this once at startup and pass the result to `JwtValidator::new`.
    pub async fn fetch_jwks(&self) -> Result<JwksResponse> {
        let response = self
            .client
            .get(format!("{}/.well-known/jwks.json", self.base_url))
            .header("Accept", "application/json")
            .header("User-Agent", "HytaleServer/1.0")
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Failed to fetch JWKS: HTTP {status} - {body}"));
        }

        Ok(response.json().await?)
    }

    /// Creates a game session for the server itself. Required before the server can
    /// authenticate players. Returns a session token (for API calls) and an identity
    /// token (to identify the server to players).
    pub async fn create_game_session(
        &self,
        oauth_access_token: &str,
        profile_uuid: &str,
    ) -> Result<GameSessionResponse> {
        let body = serde_json::json!({
            "uuid": profile_uuid
        });

        let response = self
            .client
            .post(format!("{}/game-session/new", self.base_url))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {oauth_access_token}"))
            .header("User-Agent", "HytaleServer/1.0")
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!(
                "Failed to create game session: HTTP {status} - {body}"
            ));
        }

        Ok(response.json().await?)
    }

    /// Requests an authorization grant for a player attempting to join.
    /// Called by the server after receiving a player's identity token.
    /// The grant is sent to the player, who exchanges it for an access token.
    pub async fn auth_grant(
        &self,
        identity_token: &str,
        server_audience: &str,
        bearer_token: &str,
    ) -> Result<String> {
        let body = serde_json::json!({
            "identityToken": identity_token,
            "aud": server_audience
        });

        let response = self
            .client
            .post(format!("{}/server-join/auth-grant", self.base_url))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("Authorization", format!("Bearer {bearer_token}"))
            .header("User-Agent", "HytaleServer/1.0")
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!(
                "Failed to request authorization grant: HTTP {status} - {body}"
            ));
        }

        let resp: AuthGrantResponse = response.json().await?;
        Ok(resp.authorization_grant)
    }

    /// Exchanges an authorization grant for an access token.
    /// Called by the server after the player returns their grant. The fingerprint
    /// binds the token to the server's TLS certificate for additional security.
    pub async fn auth_token(
        &self,
        authorization_grant: &str,
        x509_fingerprint: &str,
        bearer_token: &str,
    ) -> Result<String> {
        let body = serde_json::json!({
            "authorizationGrant": authorization_grant,
            "x509Fingerprint": x509_fingerprint
        });

        let response = self
            .client
            .post(format!("{}/server-join/auth-token", self.base_url))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("Authorization", format!("Bearer {bearer_token}"))
            .header("User-Agent", "HytaleServer/1.0")
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!(
                "Failed to exchange auth grant: HTTP {status} - {body}"
            ));
        }

        let resp: AccessTokenResponse = response.json().await?;
        Ok(resp.access_token)
    }
}

/// Active game session tokens obtained from `SessionClient::create_game_session`.
#[derive(Debug, Clone)]
pub struct GameSession {
    pub session_token: String,
    pub identity_token: String,
    #[allow(dead_code)]
    pub expires_at: String,
}

/// Thread-safe storage for server credentials and session state.
///
/// Holds OAuth credentials (for token refresh), the current game session,
/// and the server's certificate fingerprint. Credentials can be persisted
/// to disk and are automatically encrypted.
pub struct CredentialStore {
    oauth: RwLock<AuthCredentials>,
    game_session: RwLock<Option<GameSession>>,
    certificate_fingerprint: String,
    path: PathBuf,
    machine_id: Option<String>,
}

impl CredentialStore {
    /// Creates a new store with the given credentials and server certificate.
    /// The certificate fingerprint is computed automatically.
    pub fn new(
        creds: AuthCredentials,
        path: PathBuf,
        machine_id: Option<String>,
        server_cert: &CertificateDer<'_>,
    ) -> Self {
        Self {
            oauth: RwLock::new(creds),
            game_session: RwLock::new(None),
            certificate_fingerprint: compute_certificate_fingerprint(server_cert.as_ref()),
            path,
            machine_id,
        }
    }

    pub async fn oauth_credentials(&self) -> AuthCredentials {
        self.oauth.read().await.clone()
    }

    pub async fn update_oauth_credentials(&self, creds: AuthCredentials) {
        *self.oauth.write().await = creds;
    }

    pub async fn game_session(&self) -> Option<GameSession> {
        self.game_session.read().await.clone()
    }

    pub async fn set_game_session(&self, session: GameSession) {
        *self.game_session.write().await = Some(session);
    }

    pub async fn session_token(&self) -> Option<String> {
        self.game_session
            .read()
            .await
            .as_ref()
            .map(|s| s.session_token.clone())
    }

    pub async fn identity_token(&self) -> Option<String> {
        self.game_session
            .read()
            .await
            .as_ref()
            .map(|s| s.identity_token.clone())
    }

    pub fn certificate_fingerprint(&self) -> &str {
        &self.certificate_fingerprint
    }

    pub async fn persist_async(&self) -> Result<()> {
        let creds = self.oauth.read().await.clone();
        auth_file::save_credentials_to_file(&self.path, &creds, self.machine_id.as_deref())
    }
}
