#![allow(dead_code)]

use anyhow::{Result, anyhow};
use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::{frame_packet, read_fixed_ascii_string, read_var_int, read_var_string, write_var_int};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClientType {
    Game = 0,
    AssetEditor = 1,
}

impl From<u8> for ClientType {
    fn from(v: u8) -> Self {
        match v {
            1 => ClientType::AssetEditor,
            _ => ClientType::Game,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Connect {
    pub protocol_crc: i32,
    pub protocol_build_number: i32,
    pub client_version: String,
    pub client_type: ClientType,
    pub uuid: uuid::Uuid,
    pub username: String,
    pub identity_token: Option<String>,
    pub language: String,
    pub referral_data: Option<String>,
    pub referral_source: Option<Vec<u8>>,
}

impl Connect {
    pub const PACKET_ID: u32 = 0;
    const VARIABLE_BLOCK_START: usize = 66;

    pub fn decode(payload: &mut Bytes) -> Result<Self> {
        if payload.len() < Self::VARIABLE_BLOCK_START {
            return Err(anyhow!("Connect packet too small: {} bytes", payload.len()));
        }

        let mut buf = payload.clone();
        let null_bits = buf.get_u8();
        let protocol_crc = buf.get_i32_le();
        let protocol_build_number = buf.get_i32_le();
        let client_version = read_fixed_ascii_string(&mut buf, 20);
        let client_type = ClientType::from(buf.get_u8());
        let uuid = uuid::Uuid::from_u128(buf.get_u128());

        // Offset table
        let username_offset = buf.get_i32_le(); // Username offset
        let identity_token_offset = buf.get_i32_le(); // Identity token offset
        let language_offset = buf.get_i32_le(); // language offset
        let referral_data_offset = buf.get_i32_le(); // referral data offset
        let referral_source_offset = buf.get_i32_le(); // referral source offset

        let username = read_var_string(&mut buf.slice(username_offset as usize..)).unwrap();

        let identity_token = if null_bits & 1 != 0 && identity_token_offset >= 0 {
            let mut token_block = buf.slice(identity_token_offset as usize..);
            Some(read_var_string(&mut token_block).unwrap())
        } else {
            None
        };

        let language = read_var_string(&mut buf.slice(language_offset as usize..)).unwrap();

        let referral_data = if null_bits & 2 != 0 && referral_data_offset >= 0 {
            let mut ref_data_block = buf.slice(referral_data_offset as usize..);
            Some(read_var_string(&mut ref_data_block)?)
        } else {
            None
        };

        let referral_source = if null_bits & 4 != 0 && referral_source_offset >= 0 {
            let mut ref_source_block = buf.slice(referral_source_offset as usize..);
            let len = read_var_int(&mut ref_source_block)?;
            if len < 0 {
                return Err(anyhow!("Negative referral data length"));
            }
            let len = len as usize;
            if ref_source_block.remaining() < len {
                return Err(anyhow!("Referral data extends past buffer"));
            }
            Some(buf.copy_to_bytes(len).to_vec())
        } else {
            None
        };

        Ok(Self {
            protocol_crc,
            protocol_build_number,
            client_version,
            client_type,
            language,
            identity_token,
            uuid,
            username,
            referral_data,
            referral_source,
        })
    }
}

#[derive(Debug, Clone)]
pub struct AuthGrant {
    pub authorization_grant: Option<String>,
    pub server_identity_token: Option<String>,
}

impl AuthGrant {
    pub const PACKET_ID: u32 = 11;
    const VARIABLE_BLOCK_START: usize = 9;

    pub fn new(authorization_grant: Option<String>, server_identity_token: Option<String>) -> Self {
        Self {
            authorization_grant,
            server_identity_token,
        }
    }

    pub fn encode_packet(&self) -> Bytes {
        frame_packet(Self::PACKET_ID, &self.encode())
    }

    pub fn encode(&self) -> BytesMut {
        let mut payload = BytesMut::new();

        let mut null_bits: u8 = 0;
        if self.authorization_grant.is_some() {
            null_bits |= 1;
        }
        if self.server_identity_token.is_some() {
            null_bits |= 2;
        }
        payload.put_u8(null_bits);

        let grant_offset_pos = payload.len();
        payload.put_i32_le(0);
        let identity_offset_pos = payload.len();
        payload.put_i32_le(0);

        let var_block_start = payload.len();

        if let Some(ref grant) = self.authorization_grant {
            let offset = (payload.len() - var_block_start) as i32;
            let grant_bytes = grant.as_bytes();
            write_var_int(&mut payload, grant_bytes.len() as i32);
            payload.extend_from_slice(grant_bytes);

            let offset_bytes = offset.to_le_bytes();
            payload[grant_offset_pos..grant_offset_pos + 4].copy_from_slice(&offset_bytes);
        } else {
            payload[grant_offset_pos..grant_offset_pos + 4].copy_from_slice(&(-1i32).to_le_bytes());
        }

        if let Some(ref token) = self.server_identity_token {
            let offset = (payload.len() - var_block_start) as i32;
            let token_bytes = token.as_bytes();
            write_var_int(&mut payload, token_bytes.len() as i32);
            payload.extend_from_slice(token_bytes);

            let offset_bytes = offset.to_le_bytes();
            payload[identity_offset_pos..identity_offset_pos + 4].copy_from_slice(&offset_bytes);
        } else {
            payload[identity_offset_pos..identity_offset_pos + 4]
                .copy_from_slice(&(-1i32).to_le_bytes());
        }

        payload
    }

    pub fn decode(payload: &mut Bytes) -> Result<Self> {
        if payload.len() < Self::VARIABLE_BLOCK_START {
            return Err(anyhow!("AuthGrant packet too small"));
        }

        let data = payload.clone();
        let null_bits = payload.get_u8();
        let grant_offset = payload.get_i32_le();
        let identity_offset = payload.get_i32_le();

        let var_block = data.slice(Self::VARIABLE_BLOCK_START..);

        let authorization_grant = if null_bits & 1 != 0 && grant_offset >= 0 {
            let mut slice = var_block.slice(grant_offset as usize..);
            Some(read_var_string(&mut slice)?)
        } else {
            None
        };

        let server_identity_token = if null_bits & 2 != 0 && identity_offset >= 0 {
            let mut slice = var_block.slice(identity_offset as usize..);
            Some(read_var_string(&mut slice)?)
        } else {
            None
        };

        Ok(Self {
            authorization_grant,
            server_identity_token,
        })
    }
}

#[derive(Debug, Clone)]
pub struct AuthToken {
    pub access_token: Option<String>,
    pub server_authorization_grant: Option<String>,
}

impl AuthToken {
    pub const PACKET_ID: u32 = 12;
    const VARIABLE_BLOCK_START: usize = 9;

    pub fn new(access_token: Option<String>, server_authorization_grant: Option<String>) -> Self {
        Self {
            access_token,
            server_authorization_grant,
        }
    }

    pub fn encode_packet(&self) -> Bytes {
        frame_packet(Self::PACKET_ID, &self.encode())
    }

    pub fn encode(&self) -> BytesMut {
        let mut payload = BytesMut::new();

        let mut null_bits: u8 = 0;
        if self.access_token.is_some() {
            null_bits |= 1;
        }
        if self.server_authorization_grant.is_some() {
            null_bits |= 2;
        }
        payload.put_u8(null_bits);

        let access_offset_pos = payload.len();
        payload.put_i32_le(0);
        let grant_offset_pos = payload.len();
        payload.put_i32_le(0);

        let var_block_start = payload.len();

        if let Some(ref token) = self.access_token {
            let offset = (payload.len() - var_block_start) as i32;
            let token_bytes = token.as_bytes();
            write_var_int(&mut payload, token_bytes.len() as i32);
            payload.extend_from_slice(token_bytes);

            let offset_bytes = offset.to_le_bytes();
            payload[access_offset_pos..access_offset_pos + 4].copy_from_slice(&offset_bytes);
        } else {
            payload[access_offset_pos..access_offset_pos + 4]
                .copy_from_slice(&(-1i32).to_le_bytes());
        }

        if let Some(ref grant) = self.server_authorization_grant {
            let offset = (payload.len() - var_block_start) as i32;
            let grant_bytes = grant.as_bytes();
            write_var_int(&mut payload, grant_bytes.len() as i32);
            payload.extend_from_slice(grant_bytes);

            let offset_bytes = offset.to_le_bytes();
            payload[grant_offset_pos..grant_offset_pos + 4].copy_from_slice(&offset_bytes);
        } else {
            payload[grant_offset_pos..grant_offset_pos + 4].copy_from_slice(&(-1i32).to_le_bytes());
        }

        payload
    }

    pub fn decode(payload: &mut Bytes) -> Result<Self> {
        if payload.len() < Self::VARIABLE_BLOCK_START {
            return Err(anyhow!("AuthToken packet too small"));
        }

        let data = payload.clone();
        let null_bits = payload.get_u8();
        let access_offset = payload.get_i32_le();
        let grant_offset = payload.get_i32_le();

        let var_block = data.slice(Self::VARIABLE_BLOCK_START..);

        let access_token = if null_bits & 1 != 0 && access_offset >= 0 {
            let mut slice = var_block.slice(access_offset as usize..);
            Some(read_var_string(&mut slice)?)
        } else {
            None
        };

        let server_authorization_grant = if null_bits & 2 != 0 && grant_offset >= 0 {
            let mut slice = var_block.slice(grant_offset as usize..);
            Some(read_var_string(&mut slice)?)
        } else {
            None
        };

        Ok(Self {
            access_token,
            server_authorization_grant,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ServerAuthToken {
    pub server_access_token: Option<String>,
    pub password_challenge: Option<Vec<u8>>,
}

impl ServerAuthToken {
    pub const PACKET_ID: u32 = 13;
    const VARIABLE_BLOCK_START: usize = 9;

    pub fn new(server_access_token: Option<String>, password_challenge: Option<Vec<u8>>) -> Self {
        Self {
            server_access_token,
            password_challenge,
        }
    }

    pub fn encode_packet(&self) -> Bytes {
        frame_packet(Self::PACKET_ID, &self.encode())
    }

    pub fn encode(&self) -> BytesMut {
        let mut payload = BytesMut::new();

        let mut null_bits: u8 = 0;
        if self.server_access_token.is_some() {
            null_bits |= 1;
        }
        if self.password_challenge.is_some() {
            null_bits |= 2;
        }
        payload.put_u8(null_bits);

        let token_offset_pos = payload.len();
        payload.put_i32_le(0);
        let challenge_offset_pos = payload.len();
        payload.put_i32_le(0);

        let var_block_start = payload.len();

        if let Some(ref token) = self.server_access_token {
            let offset = (payload.len() - var_block_start) as i32;
            let token_bytes = token.as_bytes();
            write_var_int(&mut payload, token_bytes.len() as i32);
            payload.extend_from_slice(token_bytes);

            let offset_bytes = offset.to_le_bytes();
            payload[token_offset_pos..token_offset_pos + 4].copy_from_slice(&offset_bytes);
        } else {
            payload[token_offset_pos..token_offset_pos + 4].copy_from_slice(&(-1i32).to_le_bytes());
        }

        if let Some(ref challenge) = self.password_challenge {
            let offset = (payload.len() - var_block_start) as i32;
            write_var_int(&mut payload, challenge.len() as i32);
            payload.extend_from_slice(challenge);

            let offset_bytes = offset.to_le_bytes();
            payload[challenge_offset_pos..challenge_offset_pos + 4].copy_from_slice(&offset_bytes);
        } else {
            payload[challenge_offset_pos..challenge_offset_pos + 4]
                .copy_from_slice(&(-1i32).to_le_bytes());
        }

        payload
    }

    pub fn decode(payload: &mut Bytes) -> Result<Self> {
        if payload.len() < Self::VARIABLE_BLOCK_START {
            return Err(anyhow!("ServerAuthToken packet too small"));
        }

        let data = payload.clone();
        let null_bits = payload.get_u8();
        let token_offset = payload.get_i32_le();
        let challenge_offset = payload.get_i32_le();

        let var_block = data.slice(Self::VARIABLE_BLOCK_START..);

        let server_access_token = if null_bits & 1 != 0 && token_offset >= 0 {
            let mut slice = var_block.slice(token_offset as usize..);
            Some(read_var_string(&mut slice)?)
        } else {
            None
        };

        let password_challenge = if null_bits & 2 != 0 && challenge_offset >= 0 {
            let mut slice = var_block.slice(challenge_offset as usize..);
            let len = read_var_int(&mut slice)?;
            if len < 0 {
                return Err(anyhow!("Negative password challenge length"));
            }
            let len = len as usize;
            if slice.remaining() < len {
                return Err(anyhow!("Password challenge extends past buffer"));
            }
            Some(slice.copy_to_bytes(len).to_vec())
        } else {
            None
        };

        Ok(Self {
            server_access_token,
            password_challenge,
        })
    }
}
