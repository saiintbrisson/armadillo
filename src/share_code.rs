//! Hytale share code encoder/decoder.
//!
//! Share codes are Base64(deflate(JSON)) strings containing server connection info.

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD};
use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::SocketAddr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CandidateType {
    Host,
    UPnP,
    Relay,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ConnectionCandidate {
    #[serde(rename = "Type")]
    pub type_: CandidateType,
    pub address: String,
    pub port: u16,
    pub priority: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ShareCodeData {
    pub host_name: String,
    pub host_uuid: String,
    pub server_name: String,
    pub password: String,
    pub expires_at: String,
    pub candidates: Vec<ConnectionCandidate>,
}

/// Decodes a Base64+deflate+JSON share code
pub fn decode_share_code(share_code: &str) -> Result<ShareCodeData> {
    let compressed_data = STANDARD
        .decode(share_code)
        .context("Failed to decode base64")?;

    let mut decoder = DeflateDecoder::new(&compressed_data[..]);
    let mut json_bytes = Vec::new();
    decoder
        .read_to_end(&mut json_bytes)
        .context("Failed to decompress deflate data")?;

    serde_json::from_slice(&json_bytes).context("Failed to parse JSON")
}

/// Encodes share code data to Base64+deflate+JSON
pub fn encode_share_code(data: &ShareCodeData) -> Result<String> {
    let json_str = serde_json::to_string(data).context("Failed to serialize to JSON")?;

    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(json_str.as_bytes())
        .context("Failed to write to compressor")?;
    let compressed = encoder.finish().context("Failed to finish compression")?;

    Ok(STANDARD.encode(compressed))
}

/// Creates a new share code from a local server address
pub fn create_share_code(
    local_addr: SocketAddr,
    expires_in: std::time::Duration,
) -> Result<ShareCodeData> {
    let host_uuid = uuid::Uuid::new_v4().to_string();
    let host_name = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "Unknown".to_string());

    let expires_at = {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
        let expires = now + expires_in;
        let datetime = time::OffsetDateTime::from_unix_timestamp(expires.as_secs() as i64)?;
        datetime.format(&time::format_description::well_known::Iso8601::DEFAULT)?
    };

    Ok(ShareCodeData {
        host_name,
        host_uuid,
        server_name: "Proxied Server".to_string(),
        password: String::new(),
        expires_at,
        candidates: vec![ConnectionCandidate {
            type_: CandidateType::Host,
            address: local_addr.ip().to_string(),
            port: local_addr.port(),
            priority: 1000,
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE_CODE: &str = "LY7NakMhEIVfpbiuF0e9xroLpdBVKDSl0NKFjRMQkngZzR8h754xZHnON/PNXMR7qW0RtyiCWJXttG9Ictfz8x197XNiZFbWaAdewgyVtCZG6Y0x0qz/AUFF0OB54xPpgPTQLfD49F1okxh8xFqPhboKtOHi7TRlwjpv3GilnVQgYVyCCXYM4AbrwfsfHnyNu5RTbFhF+L2I5Xnq7v4aw3lKLKnd+qIHcH5QA/RzhVjsRjvTHCgXyu0sAiilrn/XGw==";

    #[test]
    fn test_decode() {
        let data = decode_share_code(EXAMPLE_CODE).unwrap();
        dbg!(&data);
        assert_eq!(data.server_name, "New World");
        assert_eq!(data.password, "123");
        assert_eq!(data.candidates.len(), 1);
    }

    #[test]
    fn test_round_trip() {
        let original = decode_share_code(EXAMPLE_CODE).unwrap();
        let encoded = encode_share_code(&original).unwrap();
        let decoded = decode_share_code(&encoded).unwrap();
        assert_eq!(original, decoded);
    }
}
