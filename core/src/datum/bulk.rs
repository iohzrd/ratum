use crate::cursor::{Cursor, Truncated};
use bytes::BufMut as _;

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
        Self::Truncated
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
        let mut w = &mut out[..];
        w.put_slice(&ACK_MARKER);
        w.put_u32_le(self.id);
        w.put_u32_le(self.next_offset);
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
        Self::default()
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

#[cfg(test)]
mod tests {
    use super::*;

    const FRAGMENT_HEADER_SIZE: usize = DBF_MARKER.len() + 3 * size_of::<u32>();

    fn encode_fragment(f: &Fragment<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(FRAGMENT_HEADER_SIZE + f.data.len());
        out.put_slice(&DBF_MARKER);
        out.put_u32_le(f.id);
        out.put_u32_le(f.total_size);
        out.put_u32_le(f.offset);
        out.put_slice(f.data);
        out
    }

    fn decode_ack(data: &[u8]) -> Option<Ack> {
        if data.len() != ACK_LEN || data[..ACK_MARKER.len()] != ACK_MARKER {
            return None;
        }
        Some(Ack {
            id: u32::from_le_bytes(data[4..8].try_into().expect("four bytes")),
            next_offset: u32::from_le_bytes(data[8..12].try_into().expect("four bytes")),
        })
    }

    fn split(id: u32, payload: &[u8]) -> Vec<Fragment<'_>> {
        payload
            .chunks(FRAGMENT_DATA_SIZE)
            .enumerate()
            .map(|(i, chunk)| Fragment {
                id,
                total_size: payload.len() as u32,
                offset: (i * FRAGMENT_DATA_SIZE) as u32,
                data: chunk,
            })
            .collect()
    }

    #[test]
    fn fragment_bytes_match_the_c_layout() {
        let f = Fragment { id: 7, total_size: 20000, offset: 16384, data: &[0xCC; 3616] };
        let b = encode_fragment(&f);
        assert_eq!(&b[..4], b"DBF\x01");
        assert_eq!(u32::from_le_bytes(b[4..8].try_into().unwrap()), 7);
        assert_eq!(u32::from_le_bytes(b[8..12].try_into().unwrap()), 20000);
        assert_eq!(u32::from_le_bytes(b[12..16].try_into().unwrap()), 16384);
        assert_eq!(b.len(), FRAGMENT_HEADER_SIZE + 3616);
        assert_eq!(Fragment::decode(&b).unwrap(), f);

        let a = Ack { id: 7, next_offset: 20000 };
        let b = a.encode();
        assert_eq!(&b[..4], b"DBA\x01");
        assert_eq!(decode_ack(&b).unwrap(), a);
        assert_eq!(decode_ack(&b[..11]), None, "an ack must be exactly 12 bytes");
    }

    #[test]
    fn a_transfer_reassembles_through_the_c_sized_fragments() {
        let payload: Vec<u8> = (0..FRAGMENT_DATA_SIZE * 3 + 5000).map(|i| i as u8).collect();
        let frags = split(3, &payload);
        assert_eq!(frags.len(), 4);
        assert!(frags[..3].iter().all(|f| f.data.len() == FRAGMENT_DATA_SIZE));
        assert_eq!(frags[3].data.len(), 5000);

        let mut r = Reassembler::new();
        for (i, f) in frags.iter().enumerate() {
            let (ack, done) = r.accept(f).unwrap();
            assert_eq!(ack.id, 3);
            assert_eq!(ack.next_offset, f.offset + f.data.len() as u32);
            match done {
                Some(got) => {
                    assert_eq!(i, frags.len() - 1);
                    assert_eq!(got, payload);
                }
                None => assert!(i < frags.len() - 1),
            }
        }
        assert!(!r.transfer.is_some());
    }

    #[test]
    fn a_fragment_that_does_not_continue_the_transfer_is_refused() {
        let payload = vec![1u8; FRAGMENT_DATA_SIZE + 10];
        let frags = split(9, &payload);
        let mut r = Reassembler::new();
        r.accept(&frags[0]).unwrap();

        let other = Fragment { id: 8, ..frags[1].clone() };
        assert_eq!(r.accept(&other), Err(Error::WrongTransfer { want: 9, got: 8 }));
        let repeat = frags[0].clone();
        assert_eq!(
            r.accept(&repeat),
            Err(Error::WrongOffset { want: FRAGMENT_DATA_SIZE as u32, got: 0 })
        );
        let resized = Fragment { total_size: 999_999, ..frags[1].clone() };
        assert!(matches!(r.accept(&resized), Err(Error::SizeChanged { .. })));
        let (_, done) = r.accept(&frags[1]).unwrap();
        assert_eq!(done.unwrap(), payload);

        assert_eq!(r.accept(&frags[1]), Err(Error::NotAtStart));
        let zero = Fragment { id: 0, total_size: 5, offset: 0, data: &[1] };
        assert_eq!(r.accept(&zero), Err(Error::ZeroId));
        let huge = Fragment { id: 1, total_size: u32::MAX, offset: 0, data: &[1] };
        assert!(matches!(r.accept(&huge), Err(Error::BadSize(_))));
        let tiny = Fragment { id: 1, total_size: 2, offset: 0, data: &[1, 2, 3] };
        assert!(matches!(r.accept(&tiny), Err(Error::BadChunk(3))));
        assert!(!r.transfer.is_some());
        let (_, done) =
            r.accept(&Fragment { id: 1, total_size: 2, offset: 0, data: &[1] }).unwrap();
        assert!(done.is_none());
        assert!(r.transfer.is_some());
        r.reset();
        assert!(!r.transfer.is_some());
    }
}
