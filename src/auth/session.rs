use anyhow::Result;
use std::path::PathBuf;
use tokio::sync::RwLock;

use crate::crypto::{self, AuthCredentials};

#[derive(Debug, Clone)]
pub struct GameSession {
    pub session_token: String,
    pub identity_token: String,
    #[allow(dead_code)]
    pub expires_at: String,
}

pub struct CredentialStore {
    oauth: RwLock<AuthCredentials>,
    game_session: RwLock<Option<GameSession>>,
    certificate_fingerprint: RwLock<Option<String>>,
    path: PathBuf,
    machine_id: Option<String>,
}

impl CredentialStore {
    pub fn new(creds: AuthCredentials, path: PathBuf, machine_id: Option<String>) -> Self {
        Self {
            oauth: RwLock::new(creds),
            game_session: RwLock::new(None),
            certificate_fingerprint: RwLock::new(None),
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

    pub async fn certificate_fingerprint(&self) -> Option<String> {
        self.certificate_fingerprint.read().await.clone()
    }

    pub async fn set_certificate_fingerprint(&self, fingerprint: String) {
        *self.certificate_fingerprint.write().await = Some(fingerprint);
    }

    pub async fn persist_async(&self) -> Result<()> {
        let creds = self.oauth.read().await.clone();
        crypto::save_credentials_to_file(&self.path, &creds, self.machine_id.as_deref())
    }
}
