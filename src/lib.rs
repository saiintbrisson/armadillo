pub mod auth;
pub mod client;
pub mod crypto;
pub mod hytale;
pub mod server;

pub use client::{UpstreamConnection, connect_upstream};
pub use crypto::{CertSource, make_server_tls_config};
pub use server::{ClientConnection, accept_client, make_server_endpoint};

pub use auth::{
    AccessClaims, CredentialStore, GameSession, IdentityClaims, JwtValidator, OAUTH_TOKEN_URL,
    OAuthClient, SESSION_SERVICE_URL, ServerIdentity, SessionClient, TokenResponse,
    compute_certificate_fingerprint, token_refresh_task,
};

pub use hytale::{
    AuthGrant, AuthToken, ClientType, Connect, HYTALE_ALPN, HytaleAuthResult, HytaleAuthenticator,
    Packet, PacketReader, ServerAuthToken, frame_packet,
};
