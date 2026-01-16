#![allow(dead_code)]

use anyhow::{Result, anyhow};
use reqwest::Client;
use serde::Deserialize;

const OAUTH_TOKEN_URL: &str = "https://oauth.accounts.hytale.com/oauth2/token";

#[derive(Debug, Deserialize)]
pub struct OAuthTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
}

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

pub struct SessionServiceClient {
    client: Client,
    base_url: String,
}

impl SessionServiceClient {
    pub fn new(base_url: &str) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        let base_url = base_url.strip_suffix('/').unwrap_or(base_url).to_string();

        Ok(Self { client, base_url })
    }

    pub async fn refresh_oauth_token(&self, refresh_token: &str) -> Result<OAuthTokenResponse> {
        let body = format!(
            "grant_type=refresh_token&client_id={}&refresh_token={}",
            urlencoding::encode("hytale-server"),
            urlencoding::encode(refresh_token)
        );

        let response = self
            .client
            .post(OAUTH_TOKEN_URL)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("User-Agent", "HytaleServer/1.0")
            .body(body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Token refresh failed: HTTP {status} - {body}"));
        }

        Ok(response.json().await?)
    }

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

    pub async fn request_authorization_grant(
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

    pub async fn exchange_auth_grant(
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

    pub async fn get_jwks(&self) -> Result<JwksResponse> {
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
