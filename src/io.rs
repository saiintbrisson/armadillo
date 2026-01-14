//! QUIC stream IO helpers

use anyhow::Result;
use quinn::{RecvStream, SendStream};

pub async fn send_json<T: serde::Serialize>(send: &mut SendStream, msg: &T) -> Result<()> {
    let json = serde_json::to_vec(msg)?;
    let len = (json.len() as u32).to_be_bytes();

    send.write_all(&len).await?;
    send.write_all(&json).await?;

    Ok(())
}

pub async fn recv_json<T: serde::de::DeserializeOwned>(recv: &mut RecvStream) -> Result<T> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut json_buf = vec![0u8; len];
    recv.read_exact(&mut json_buf).await?;

    serde_json::from_slice(&json_buf).map_err(Into::into)
}
