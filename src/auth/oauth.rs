use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::Deserialize;
use tracing::{error, info, warn};

use super::CredentialStore;
use crate::crypto::auth_file::AuthCredentials;

pub const OAUTH_TOKEN_URL: &str = "https://oauth.accounts.hytale.com/oauth2/token";
const REFRESH_MARGIN: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
}

/// HTTP client for Hytale's OAuth service at `https://oauth.accounts.hytale.com`.
///
/// Used to refresh OAuth tokens before they expire. Servers need valid OAuth tokens
/// to create game sessions via `SessionClient`. For automatic refresh, use
/// `token_refresh_task` instead of calling this directly.
pub struct OAuthClient {
    client: Client,
    token_endpoint: String,
}

impl OAuthClient {
    /// Creates a client pointing to the production OAuth service.
    pub fn new() -> Result<Self> {
        Self::with_endpoint(OAUTH_TOKEN_URL)
    }

    /// Creates a client with a custom token endpoint.
    pub fn with_endpoint(token_endpoint: &str) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        Ok(Self {
            client,
            token_endpoint: token_endpoint.to_string(),
        })
    }

    /// Exchanges a refresh token for new access and refresh tokens.
    pub async fn refresh(&self, refresh_token: &str) -> Result<TokenResponse> {
        let body = format!(
            "grant_type=refresh_token&client_id={}&refresh_token={}",
            urlencoding::encode("hytale-server"),
            urlencoding::encode(refresh_token)
        );

        let response = self
            .client
            .post(&self.token_endpoint)
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
}

/// Long-running task that automatically refreshes OAuth tokens before expiry.
///
/// Spawns this as a background task at server startup. It monitors the credential
/// store and refreshes tokens 5 minutes before they expire, persisting the new
/// credentials to disk.
///
/// ```ignore
/// let store = Arc::new(CredentialStore::new(...));
/// tokio::spawn(token_refresh_task(store.clone()));
/// ```
pub async fn token_refresh_task(store: Arc<CredentialStore>) {
    let client = match OAuthClient::new() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create OAuth client for token refresh: {e}");
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
        match client.refresh(&oauth.refresh_token).await {
            Ok(response) => {
                let new_expires = Utc::now() + chrono::Duration::seconds(response.expires_in);
                let updated = AuthCredentials {
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
