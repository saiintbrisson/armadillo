use anyhow::{Result, anyhow};
use bytes::{Buf, BufMut, Bytes, BytesMut};

pub const FRAME_HEADER_SIZE: usize = 8;

#[derive(Debug, Clone)]
pub struct Packet {
    pub id: u32,
    pub payload: Bytes,
}

pub fn write_packet(packet: &Packet) -> Bytes {
    frame_packet(packet.id, &packet.payload)
}

pub fn frame_packet(id: u32, payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(FRAME_HEADER_SIZE + payload.len());
    buf.put_u32_le(payload.len() as u32);
    buf.put_u32_le(id);
    buf.extend_from_slice(payload);
    buf.freeze()
}

pub struct PacketReader {
    buffer: BytesMut,
}

impl PacketReader {
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(65536),
        }
    }

    pub fn buffer_mut(&mut self) -> &mut BytesMut {
        &mut self.buffer
    }

    pub fn try_parse_packet(&mut self) -> Result<Option<Packet>> {
        if self.buffer.len() < FRAME_HEADER_SIZE {
            return Ok(None);
        }

        let length = (&self.buffer[..4]).get_u32_le() as usize;
        let total_len = FRAME_HEADER_SIZE + length;
        if self.buffer.len() < total_len {
            return Ok(None);
        }

        self.buffer.advance(4);
        let id = self.buffer.get_u32_le();
        let payload = self.buffer.split_to(length).freeze();

        Ok(Some(Packet { id, payload }))
    }
}

#[derive(Debug, Clone)]
pub struct RawPacket {
    pub id: u32,
    pub payload_len: u32,
    pub bytes: Bytes,
}

pub struct RawPacketReader {
    buffer: BytesMut,
}

impl RawPacketReader {
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(65536),
        }
    }

    pub fn buffer_mut(&mut self) -> &mut BytesMut {
        &mut self.buffer
    }

    pub fn try_read_packet(&mut self) -> Result<Option<RawPacket>> {
        if self.buffer.len() < FRAME_HEADER_SIZE {
            return Ok(None);
        }

        let payload_len = (&self.buffer[..4]).get_u32_le();
        let id = (&self.buffer[4..8]).get_u32_le();
        let total_len = FRAME_HEADER_SIZE + payload_len as usize;

        if self.buffer.len() < total_len {
            return Ok(None);
        }

        let bytes = self.buffer.split_to(total_len).freeze();
        Ok(Some(RawPacket {
            id,
            payload_len,
            bytes,
        }))
    }
}

pub fn read_var_int(buf: &mut Bytes) -> Result<i32> {
    let mut result: i32 = 0;
    let mut shift = 0;

    loop {
        if !buf.has_remaining() {
            return Err(anyhow!("VarInt extends past end of buffer"));
        }

        let byte = buf.get_u8();
        result |= ((byte & 0x7F) as i32) << shift;

        if byte & 0x80 == 0 {
            break;
        }

        shift += 7;
        if shift >= 35 {
            return Err(anyhow!("VarInt is too large"));
        }
    }

    Ok(result)
}

pub fn write_var_int(buf: &mut BytesMut, mut value: i32) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;

        if value != 0 {
            byte |= 0x80;
        }

        buf.put_u8(byte);

        if value == 0 {
            break;
        }
    }
}

pub fn read_var_string(buf: &mut Bytes) -> Result<String> {
    let len = read_var_int(buf)?;
    if len < 0 {
        return Err(anyhow!("Negative string length: {len}"));
    }

    let len = len as usize;
    if buf.remaining() < len {
        return Err(anyhow!("String extends past end of buffer"));
    }

    let bytes = buf.copy_to_bytes(len);
    Ok(String::from_utf8(bytes.to_vec())?)
}

pub fn read_fixed_ascii_string(buf: &mut Bytes, length: usize) -> String {
    if buf.remaining() < length {
        return String::new();
    }

    let bytes = buf.copy_to_bytes(length);
    let null_pos = bytes.iter().position(|&b| b == 0).unwrap_or(length);
    String::from_utf8_lossy(&bytes[..null_pos]).to_string()
}
