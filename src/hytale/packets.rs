mod auth;

pub use auth::{AuthGrant, AuthToken, ClientType, Connect, ServerAuthToken};

use anyhow::{Result, anyhow};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use quinn::RecvStream;
use tokio::io::AsyncReadExt;

pub const FRAME_HEADER_SIZE: usize = 8;

/// A length-prefixed protocol packet.
///
/// Frame format: `[4-byte len][4-byte id][payload]`
///
/// Use `frame()` to get the complete frame for transmission, or `payload()`
/// to access just the packet data.
pub struct Packet {
    frame: Bytes,
}

impl Packet {
    /// Wraps an existing frame buffer as a Packet after validating its structure.
    ///
    /// Returns an error if the frame is smaller than the header size or if the
    /// length field doesn't match the actual payload size.
    pub fn from_frame(frame: Bytes) -> Result<Self> {
        if frame.len() < FRAME_HEADER_SIZE {
            return Err(anyhow!(
                "Frame too small: {} bytes, need at least {}",
                frame.len(),
                FRAME_HEADER_SIZE
            ));
        }

        let reported_len = u32::from_le_bytes(frame[0..4].try_into().unwrap()) as usize;
        let actual_len = frame.len() - FRAME_HEADER_SIZE;

        if reported_len != actual_len {
            return Err(anyhow!(
                "Frame length mismatch: header says {} bytes, actual payload is {}",
                reported_len,
                actual_len
            ));
        }

        Ok(Self { frame })
    }

    /// Creates a new packet with the given id and payload.
    pub fn new(id: u32, payload: &[u8]) -> Result<Self> {
        Self::from_frame(frame_packet(id, payload))
    }

    /// Returns the payload length from the frame header.
    pub fn len(&self) -> u32 {
        u32::from_le_bytes(self.frame[0..4].try_into().unwrap())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the packet id from the frame header.
    pub fn id(&self) -> u32 {
        u32::from_le_bytes(self.frame[4..8].try_into().unwrap())
    }

    /// Returns the complete frame including header, for transmission.
    pub fn frame(&self) -> &Bytes {
        &self.frame
    }

    /// Returns just the payload data, without the header.
    pub fn payload(&self) -> Bytes {
        self.frame.slice(8..)
    }

    /// Consumes the packet and returns the frame bytes.
    pub fn into_frame(self) -> Bytes {
        self.frame
    }
}

/// Handles partial reads and buffering internally. Use `read_packet()` for
/// blocking reads or `try_read_packet()` to check for buffered data.
///
/// ```ignore
/// let mut reader = PacketReader::new(recv_stream);
/// loop {
///     let packet = reader.read_packet().await?;
///     println!("Got packet id={}", packet.id());
/// }
/// ```
pub struct PacketReader {
    recv: RecvStream,
    buffer: BytesMut,
}

impl PacketReader {
    pub fn new(recv: RecvStream) -> Self {
        Self {
            recv,
            buffer: BytesMut::with_capacity(65536),
        }
    }

    /// Reads the next complete packet, blocking until available.
    pub async fn read_packet(&mut self) -> Result<Packet> {
        loop {
            if let Some(packet) = self.try_read_packet()? {
                return Ok(packet);
            }

            let n = self.recv.read_buf(&mut self.buffer).await?;
            if n == 0 {
                return Err(anyhow!("Connection closed with incomplete packet"));
            }
        }
    }

    /// Returns a packet if one is complete in the buffer, without blocking.
    pub fn try_read_packet(&mut self) -> Result<Option<Packet>> {
        if self.buffer.len() < FRAME_HEADER_SIZE {
            return Ok(None);
        }

        let payload_len = (&self.buffer[..4]).get_u32_le() as usize;
        let total_len = FRAME_HEADER_SIZE + payload_len;

        if self.buffer.len() < total_len {
            return Ok(None);
        }

        let frame = self.buffer.split_to(total_len).freeze();
        Ok(Some(Packet::from_frame(frame)?))
    }

    pub fn inner(&mut self) -> &mut RecvStream {
        &mut self.recv
    }

    pub fn into_inner(self) -> RecvStream {
        self.recv
    }
}

/// Encodes a packet id and payload into a framed buffer ready for transmission.
///
/// ```ignore
/// let frame = frame_packet(1, b"hello");
/// send_stream.write_all(&frame).await?;
/// ```
pub fn frame_packet(id: u32, payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(FRAME_HEADER_SIZE + payload.len());
    buf.put_u32_le(payload.len() as u32);
    buf.put_u32_le(id);
    buf.extend_from_slice(payload);
    buf.freeze()
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
