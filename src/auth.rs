mod jwt;
mod oauth;
mod session;

pub use jwt::{AccessClaims, IdentityClaims, JwtValidator, Profile};
pub use oauth::{OAUTH_TOKEN_URL, OAuthClient, TokenResponse, token_refresh_task};
pub use session::{
    CredentialStore, GameSession, JwkKey, JwksResponse, SESSION_SERVICE_URL, SessionClient,
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

/// Server identity used during authentication handshakes.
///
/// The `server_id` identifies this server instance, while `audience` is the
/// expected audience claim in JWT tokens issued for this server.
pub struct ServerIdentity {
    pub server_id: String,
    pub audience: String,
}

impl Default for ServerIdentity {
    fn default() -> Self {
        Self {
            server_id: "armadillo".to_string(),
            audience: "hytale:server:armadillo".to_string(),
        }
    }
}

/// Computes a SHA-256 fingerprint of a DER-encoded certificate.
///
/// The fingerprint is used for certificate-bound token validation, where
/// access tokens are tied to a specific client certificate. Returns the
/// hash as a URL-safe base64 string (no padding).
///
/// ```ignore
/// let cert_der = server_cert.as_ref();
/// let fingerprint = compute_certificate_fingerprint(cert_der);
/// // fingerprint can be compared against cnf.x5t#S256 claim in JWTs
/// ```
pub fn compute_certificate_fingerprint(cert_der: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    let hash = hasher.finalize();
    URL_SAFE_NO_PAD.encode(hash)
}
