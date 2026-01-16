mod jwt;
mod oauth;
mod session;

pub use jwt::JwtValidator;
pub use oauth::SessionServiceClient;
pub use session::{CredentialStore, GameSession};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

pub fn compute_certificate_fingerprint(cert_der: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    let hash = hasher.finalize();
    URL_SAFE_NO_PAD.encode(hash)
}
