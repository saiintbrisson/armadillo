mod handshake;
mod packets;

pub use handshake::{HytaleAuthResult, HytaleAuthenticator};
pub use packets::{
    AuthGrant, AuthToken, ClientType, Connect, Packet, PacketReader, ServerAuthToken, frame_packet,
};

pub const HYTALE_ALPN: &[u8] = b"hytale/2";
