#![allow(dead_code)]

use anyhow::{Result, anyhow};
use bytes::{Buf, Bytes};

use super::io::{read_fixed_ascii_string, read_var_int, read_var_string};

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
    pub protocol_hash: String,
    pub client_type: ClientType,
    pub language: Option<String>,
    pub identity_token: Option<String>,
    pub uuid: uuid::Uuid,
    pub username: String,
    pub referral_source: Option<String>,
    pub referral_data: Option<Vec<u8>>,
}

impl Connect {
    pub const PACKET_ID: u32 = 0;
    const VARIABLE_BLOCK_START: usize = 102;

    pub fn decode(payload: Bytes) -> Result<Self> {
        if payload.len() < Self::VARIABLE_BLOCK_START {
            return Err(anyhow!("Connect packet too small: {} bytes", payload.len()));
        }

        let mut buf = payload.clone();
        let null_bits = buf.get_u8();
        let protocol_hash = read_fixed_ascii_string(&mut buf, 64);
        let client_type = ClientType::from(buf.get_u8());
        let uuid = uuid::Uuid::from_u128(buf.get_u128());

        let language_offset = buf.get_i32_le();
        let identity_offset = buf.get_i32_le();
        let username_offset = buf.get_i32_le();
        let referral_source_offset = buf.get_i32_le();
        let referral_data_offset = buf.get_i32_le();

        let var_block = payload.slice(Self::VARIABLE_BLOCK_START..);

        let language = if null_bits & 1 != 0 && language_offset >= 0 {
            let mut slice = var_block.slice(language_offset as usize..);
            Some(read_var_string(&mut slice)?)
        } else {
            None
        };

        let identity_token = if null_bits & 2 != 0 && identity_offset >= 0 {
            let mut slice = var_block.slice(identity_offset as usize..);
            Some(read_var_string(&mut slice)?)
        } else {
            None
        };

        let username = {
            let mut slice = var_block.slice(username_offset as usize..);
            read_var_string(&mut slice)?
        };

        let referral_source = if null_bits & 4 != 0 && referral_source_offset >= 0 {
            let mut slice = var_block.slice(referral_source_offset as usize..);
            Some(read_var_string(&mut slice)?)
        } else {
            None
        };

        let referral_data = if null_bits & 8 != 0 && referral_data_offset >= 0 {
            let mut slice = var_block.slice(referral_data_offset as usize..);
            let len = read_var_int(&mut slice)?;
            if len < 0 {
                return Err(anyhow!("Negative referral data length"));
            }
            let len = len as usize;
            if slice.remaining() < len {
                return Err(anyhow!("Referral data extends past buffer"));
            }
            Some(slice.copy_to_bytes(len).to_vec())
        } else {
            None
        };

        Ok(Self {
            protocol_hash,
            client_type,
            language,
            identity_token,
            uuid,
            username,
            referral_source,
            referral_data,
        })
    }
}
