use crate::cursor::{Cursor, Truncated};

pub use super::messages::DBF_MARKER;

pub const ACK_MARKER: [u8; 4] = *b"DBA\x01";
pub const FRAGMENT_DATA_SIZE: usize = 16 * 1024;
pub const MAX_TRANSFER_SIZE: usize = super::framing::MAX_CMD_DATA_SIZE as usize;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("not a bulk fragment")]
    BadMarker,
    #[error("bulk fragment shorter than its header")]
    Truncated,
    #[error("bulk fragment data length {0} out of range")]
    BadChunk(usize),
    #[error("bulk transfer id 0")]
    ZeroId,
    #[error("bulk transfer size {0} out of range")]
    BadSize(u32),
    #[error("fragment for transfer {got}, transfer {want} in progress")]
    WrongTransfer { want: u32, got: u32 },
    #[error("fragment at offset {got}, expected {want}")]
    WrongOffset { want: u32, got: u32 },
    #[error("fragment size {got} does not match the transfer's {want}")]
    SizeChanged { want: u32, got: u32 },
    #[error("first fragment does not start at offset 0")]
    NotAtStart,
}

impl From<Truncated> for Error {
    fn from(_: Truncated) -> Self {
        Error::Truncated
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fragment<'a> {
    pub id: u32,
    pub total_size: u32,
    pub offset: u32,
    pub data: &'a [u8],
}

impl<'a> Fragment<'a> {
    pub fn decode(data: &'a [u8]) -> Result<Self, Error> {
        let mut c = Cursor::new(data);
        if c.arr::<{ DBF_MARKER.len() }>("marker")? != DBF_MARKER {
            return Err(Error::BadMarker);
        }
        let id = c.u32("transfer id")?;
        let total_size = c.u32("total size")?;
        let offset = c.u32("offset")?;
        let chunk = c.rest();
        if chunk.is_empty() || chunk.len() > FRAGMENT_DATA_SIZE {
            return Err(Error::BadChunk(chunk.len()));
        }
        Ok(Fragment { id, total_size, offset, data: chunk })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ack {
    pub id: u32,
    pub next_offset: u32,
}

pub const ACK_LEN: usize = ACK_MARKER.len() + 2 * size_of::<u32>();

impl Ack {
    pub fn encode(&self) -> [u8; ACK_LEN] {
        let mut out = [0u8; ACK_LEN];
        let (marker, rest) = out.split_at_mut(ACK_MARKER.len());
        let (id, next_offset) = rest.split_at_mut(size_of::<u32>());
        marker.copy_from_slice(&ACK_MARKER);
        id.copy_from_slice(&self.id.to_le_bytes());
        next_offset.copy_from_slice(&self.next_offset.to_le_bytes());
        out
    }
}

#[derive(Debug, Default)]
pub struct Reassembler {
    transfer: Option<Transfer>,
}

#[derive(Debug)]
struct Transfer {
    id: u32,
    total_size: u32,
    buf: Vec<u8>,
}

impl Reassembler {
    pub fn new() -> Self {
        Reassembler::default()
    }

    pub fn accept(&mut self, f: &Fragment<'_>) -> Result<(Ack, Option<Vec<u8>>), Error> {
        if f.id == 0 {
            return Err(Error::ZeroId);
        }
        if f.total_size == 0 || f.total_size as usize > MAX_TRANSFER_SIZE {
            return Err(Error::BadSize(f.total_size));
        }
        let received = match &self.transfer {
            None => {
                if f.offset != 0 {
                    return Err(Error::NotAtStart);
                }
                0
            }
            Some(t) => {
                if t.id != f.id {
                    return Err(Error::WrongTransfer { want: t.id, got: f.id });
                }
                if t.total_size != f.total_size {
                    return Err(Error::SizeChanged { want: t.total_size, got: f.total_size });
                }
                if t.buf.len() as u32 != f.offset {
                    return Err(Error::WrongOffset { want: t.buf.len() as u32, got: f.offset });
                }
                t.buf.len()
            }
        };
        if received + f.data.len() > f.total_size as usize {
            return Err(Error::BadChunk(f.data.len()));
        }
        let t = self.transfer.get_or_insert_with(|| Transfer {
            id: f.id,
            total_size: f.total_size,
            buf: Vec::new(),
        });
        t.buf.extend_from_slice(f.data);
        let ack = Ack { id: t.id, next_offset: t.buf.len() as u32 };
        let done = t.buf.len() as u32 == t.total_size;
        let payload = done.then(|| self.transfer.take().expect("in progress").buf);
        Ok((ack, payload))
    }

    pub fn reset(&mut self) {
        self.transfer = None;
    }
}
