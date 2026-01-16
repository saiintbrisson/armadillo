#![allow(dead_code)]

use anyhow::{Result, anyhow};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use super::oauth::{JwkKey, SessionServiceClient};

const CLOCK_SKEW_SECONDS: i64 = 300;

#[derive(Debug, Clone, Deserialize)]
pub struct Profile {
    pub username: Option<String>,
    pub uuid: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct CertificateBinding {
    #[serde(rename = "x5t#S256")]
    fingerprint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawClaims {
    iss: Option<String>,
    aud: Option<Audience>,
    iat: Option<i64>,
    exp: Option<i64>,
    nbf: Option<i64>,
    profile: Option<Profile>,
    cnf: Option<CertificateBinding>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

impl Audience {
    fn first(&self) -> Option<&str> {
        match self {
            Audience::Single(s) => Some(s),
            Audience::Multiple(v) => v.first().map(|s| s.as_str()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IdentityTokenClaims {
    pub issuer: Option<String>,
    pub profile: Option<Profile>,
    pub expires_at: Option<i64>,
}

impl IdentityTokenClaims {
    pub fn username(&self) -> Option<&str> {
        self.profile.as_ref().and_then(|p| p.username.as_deref())
    }
}

#[derive(Debug, Clone)]
pub struct AccessTokenClaims {
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub profile: Option<Profile>,
    pub expires_at: Option<i64>,
    pub certificate_fingerprint: Option<String>,
}

impl AccessTokenClaims {
    pub fn username(&self) -> Option<&str> {
        self.profile.as_ref().and_then(|p| p.username.as_deref())
    }
}

pub struct JwtValidator {
    session_client: SessionServiceClient,
    expected_issuer: String,
    expected_audience: String,
    jwks_cache: RwLock<Option<Arc<Vec<JwkKey>>>>,
}

impl JwtValidator {
    pub fn new(session_service_url: &str, expected_audience: &str) -> Self {
        Self {
            session_client: SessionServiceClient::new(session_service_url)
                .expect("Failed to create session client"),
            expected_issuer: session_service_url.to_string(),
            expected_audience: expected_audience.to_string(),
            jwks_cache: RwLock::new(None),
        }
    }

    async fn get_jwks(&self) -> Result<Arc<Vec<JwkKey>>> {
        if let Some(keys) = self.jwks_cache.read().await.clone() {
            return Ok(keys);
        }

        let jwks = self.session_client.get_jwks().await?;
        let keys = Arc::new(jwks.keys);
        *self.jwks_cache.write().await = Some(keys.clone());
        Ok(keys)
    }

    fn decode_jwt<T: for<'de> Deserialize<'de>>(token: &str) -> Result<T> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(anyhow!("Invalid JWT format"));
        }
        let payload = URL_SAFE_NO_PAD.decode(parts[1])?;
        Ok(serde_json::from_slice(&payload)?)
    }

    async fn verify_signature(&self, token: &str) -> Result<bool> {
        #[derive(Deserialize)]
        struct Header {
            alg: String,
            kid: Option<String>,
        }

        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(anyhow!("Invalid JWT format"));
        }

        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0])?;
        let header: Header = serde_json::from_slice(&header_bytes)?;

        if header.alg != "EdDSA" {
            return Err(anyhow!(
                "Unsupported algorithm: {} (expected EdDSA)",
                header.alg
            ));
        }

        let keys = self.get_jwks().await?;
        let key = keys
            .iter()
            .find(|k| {
                k.kty == "OKP"
                    && k.crv.as_deref() == Some("Ed25519")
                    && (header.kid.is_none() || k.kid == header.kid)
            })
            .ok_or_else(|| anyhow!("No suitable Ed25519 key found in JWKS"))?;

        let x_bytes =
            URL_SAFE_NO_PAD.decode(key.x.as_ref().ok_or_else(|| anyhow!("Missing x in JWK"))?)?;

        let key_bytes: [u8; 32] = x_bytes
            .try_into()
            .map_err(|_| anyhow!("Invalid Ed25519 public key length"))?;

        let verifying_key = VerifyingKey::from_bytes(&key_bytes)?;
        let message = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2])?;
        let signature = Signature::from_slice(&sig_bytes)?;

        match verifying_key.verify_strict(message.as_bytes(), &signature) {
            Ok(()) => Ok(true),
            Err(e) => {
                debug!("Signature verification failed: {e}");
                Ok(false)
            }
        }
    }

    pub async fn validate_identity_token(&self, token: &str) -> Result<IdentityTokenClaims> {
        if token.is_empty() {
            return Err(anyhow!("Identity token is empty"));
        }

        if !self.verify_signature(token).await? {
            return Err(anyhow!("Identity token signature verification failed"));
        }

        let raw: RawClaims = Self::decode_jwt(token)?;

        if raw.iss.as_deref() != Some(&self.expected_issuer) {
            return Err(anyhow!(
                "Invalid issuer: expected {}, got {:?}",
                self.expected_issuer,
                raw.iss
            ));
        }

        let now = chrono::Utc::now().timestamp();
        let exp = raw
            .exp
            .ok_or_else(|| anyhow!("Identity token missing expiration"))?;
        if now >= exp + CLOCK_SKEW_SECONDS {
            return Err(anyhow!("Identity token expired"));
        }

        if let Some(nbf) = raw.nbf
            && now < nbf - CLOCK_SKEW_SECONDS
        {
            return Err(anyhow!("Identity token not yet valid"));
        }

        if let Some(iat) = raw.iat
            && iat > now + CLOCK_SKEW_SECONDS
        {
            return Err(anyhow!("Identity token issued in the future"));
        }

        Ok(IdentityTokenClaims {
            issuer: raw.iss,
            profile: raw.profile,
            expires_at: raw.exp,
        })
    }

    pub async fn validate_access_token(
        &self,
        token: &str,
        client_cert_fingerprint: Option<&str>,
    ) -> Result<AccessTokenClaims> {
        if token.is_empty() {
            return Err(anyhow!("Access token is empty"));
        }

        if !self.verify_signature(token).await? {
            return Err(anyhow!("Access token signature verification failed"));
        }

        let raw: RawClaims = Self::decode_jwt(token)?;

        if raw.iss.as_deref() != Some(&self.expected_issuer) {
            return Err(anyhow!(
                "Invalid issuer: expected {}, got {:?}",
                self.expected_issuer,
                raw.iss
            ));
        }

        let audience = raw.aud.as_ref().and_then(|a| a.first()).map(String::from);
        if audience.as_deref() != Some(&self.expected_audience) {
            return Err(anyhow!(
                "Invalid audience: expected {}, got {:?}",
                self.expected_audience,
                audience
            ));
        }

        let now = chrono::Utc::now().timestamp();
        if let Some(exp) = raw.exp
            && now >= exp + CLOCK_SKEW_SECONDS
        {
            return Err(anyhow!("Access token expired"));
        }

        if let Some(nbf) = raw.nbf
            && now < nbf - CLOCK_SKEW_SECONDS
        {
            return Err(anyhow!("Access token not yet valid"));
        }

        if let Some(iat) = raw.iat
            && iat > now + CLOCK_SKEW_SECONDS
        {
            return Err(anyhow!("Access token issued in the future"));
        }

        let cert_fp = raw.cnf.and_then(|c| c.fingerprint);
        if let Some(ref expected_fp) = cert_fp {
            match client_cert_fingerprint {
                Some(actual) if actual == expected_fp => {}
                Some(actual) => {
                    return Err(anyhow!(
                        "Certificate fingerprint mismatch: expected {expected_fp}, got {actual}"
                    ));
                }
                None => {
                    warn!(
                        "Token requires certificate binding but client did not present a certificate"
                    );
                }
            }
        }

        Ok(AccessTokenClaims {
            issuer: raw.iss,
            audience,
            profile: raw.profile,
            expires_at: raw.exp,
            certificate_fingerprint: cert_fp,
        })
    }
}
