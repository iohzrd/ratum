//! Bulk framing (version 3 protocol, command 6). A gateway that received `DBF\x01` after
//! the config terminator sends large replies as sequential `DBF\x01` fragments and waits
//! for a `DBA\x01` acknowledgement after each one: stop-and-wait, one transfer at a time,
//! offsets strictly ascending. The reassembled payload is byte-identical to the command-5
//! payload it replaces and is dispatched the same way.

pub use super::messages::DBF_MARKER;

/// The marker of an acknowledgement.
pub const ACK_MARKER: [u8; 4] = *b"DBA\x01";
/// `DATUM_BULK_FRAGMENT_HEADER_SIZE`.
pub const FRAGMENT_HEADER_SIZE: usize = 16;
/// `DATUM_BULK_FRAGMENT_DATA_SIZE`.
pub const FRAGMENT_DATA_SIZE: usize = 16 * 1024;
/// The C sender refuses transfers at or above `DATUM_PROTOCOL_MAX_CMD_DATA_SIZE`.
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

/// One `DBF\x01` fragment. `total_size` is constant across a transfer; `data` is
/// `min(remaining, 16384)` bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fragment<'a> {
    pub id: u32,
    pub total_size: u32,
    pub offset: u32,
    pub data: &'a [u8],
}

impl<'a> Fragment<'a> {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FRAGMENT_HEADER_SIZE + self.data.len());
        out.extend_from_slice(&DBF_MARKER);
        out.extend_from_slice(&self.id.to_le_bytes());
        out.extend_from_slice(&self.total_size.to_le_bytes());
        out.extend_from_slice(&self.offset.to_le_bytes());
        out.extend_from_slice(self.data);
        out
    }

    pub fn decode(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < FRAGMENT_HEADER_SIZE {
            return Err(Error::Truncated);
        }
        if data[..4] != DBF_MARKER {
            return Err(Error::BadMarker);
        }
        let chunk = &data[FRAGMENT_HEADER_SIZE..];
        if chunk.is_empty() || chunk.len() > FRAGMENT_DATA_SIZE {
            return Err(Error::BadChunk(chunk.len()));
        }
        Ok(Fragment {
            id: u32::from_le_bytes(data[4..8].try_into().expect("four bytes")),
            total_size: u32::from_le_bytes(data[8..12].try_into().expect("four bytes")),
            offset: u32::from_le_bytes(data[12..16].try_into().expect("four bytes")),
            data: chunk,
        })
    }
}

/// One `DBA\x01` acknowledgement. `next_offset` is the byte position of the next fragment,
/// equal to the total size after the final one. The C sender ignores an ack whose length is
/// not exactly 12.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ack {
    pub id: u32,
    pub next_offset: u32,
}

pub const ACK_LEN: usize = 12;

impl Ack {
    pub fn encode(&self) -> [u8; ACK_LEN] {
        let mut out = [0u8; ACK_LEN];
        out[..4].copy_from_slice(&ACK_MARKER);
        out[4..8].copy_from_slice(&self.id.to_le_bytes());
        out[8..].copy_from_slice(&self.next_offset.to_le_bytes());
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        if data.len() != ACK_LEN {
            return Err(Error::Truncated);
        }
        if data[..4] != ACK_MARKER {
            return Err(Error::BadMarker);
        }
        Ok(Ack {
            id: u32::from_le_bytes(data[4..8].try_into().expect("four bytes")),
            next_offset: u32::from_le_bytes(data[8..12].try_into().expect("four bytes")),
        })
    }
}

/// Split a payload into the fragments the C sender would emit. The caller supplies the
/// transfer id (the C client counts up from 1, skipping 0, across reconnects).
pub fn split(id: u32, payload: &[u8]) -> Vec<Fragment<'_>> {
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

/// The receiving (pool) side of one connection's bulk channel. At most one transfer is in
/// progress; a fragment that does not continue it is refused without resetting it, which
/// matches the C sender's behavior of stalling rather than retrying.
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

    /// Accept one fragment. Returns the ack to send and, on the final fragment, the
    /// reassembled payload. Every check precedes the insert, so a refused first fragment
    /// leaves no transfer in progress.
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

    /// Discard a partial transfer. The C client abandons an incomplete transfer on
    /// disconnect and never resumes it.
    pub fn reset(&mut self) {
        self.transfer = None;
    }

    pub fn in_progress(&self) -> bool {
        self.transfer.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragment_bytes_match_the_c_layout() {
        let f = Fragment { id: 7, total_size: 20000, offset: 16384, data: &[0xCC; 3616] };
        let b = f.encode();
        assert_eq!(&b[..4], b"DBF\x01");
        assert_eq!(u32::from_le_bytes(b[4..8].try_into().unwrap()), 7);
        assert_eq!(u32::from_le_bytes(b[8..12].try_into().unwrap()), 20000);
        assert_eq!(u32::from_le_bytes(b[12..16].try_into().unwrap()), 16384);
        assert_eq!(b.len(), 16 + 3616);
        assert_eq!(Fragment::decode(&b).unwrap(), f);

        let a = Ack { id: 7, next_offset: 20000 };
        let b = a.encode();
        assert_eq!(&b[..4], b"DBA\x01");
        assert_eq!(Ack::decode(&b).unwrap(), a);
        assert!(Ack::decode(&b[..11]).is_err(), "an ack must be exactly 12 bytes");
    }

    #[test]
    fn a_transfer_reassembles_through_the_c_sized_fragments() {
        // The C test uses MAX_CMD_DATA_SIZE - 1024: 256 full fragments and one of 12288.
        // Sized down here: three full fragments and a remainder.
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
        assert!(!r.in_progress());
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
        // The transfer is unchanged and still completes.
        let (_, done) = r.accept(&frags[1]).unwrap();
        assert_eq!(done.unwrap(), payload);

        // A new transfer must start at offset 0, with a nonzero declared size within range.
        assert_eq!(r.accept(&frags[1]), Err(Error::NotAtStart));
        let zero = Fragment { id: 0, total_size: 5, offset: 0, data: &[1] };
        assert_eq!(r.accept(&zero), Err(Error::ZeroId));
        let huge = Fragment { id: 1, total_size: u32::MAX, offset: 0, data: &[1] };
        assert!(matches!(r.accept(&huge), Err(Error::BadSize(_))));
        // More data than the declared size is refused, and a refused first fragment starts
        // no transfer.
        let tiny = Fragment { id: 1, total_size: 2, offset: 0, data: &[1, 2, 3] };
        assert!(matches!(r.accept(&tiny), Err(Error::BadChunk(3))));
        assert!(!r.in_progress());
        let (_, done) =
            r.accept(&Fragment { id: 1, total_size: 2, offset: 0, data: &[1] }).unwrap();
        assert!(done.is_none());
        assert!(r.in_progress());
        r.reset();
        assert!(!r.in_progress());
    }
}
