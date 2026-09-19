//! The frame on the wire: a four-byte header masked by a ratchet both sides advance in step, the
//! body whose length it gives, and the nonces and header keys both sides derive from the `nk` the
//! hello carries. `read_next_frame` and `read_frame` take one frame off a socket.

use crate::poll::PolledSocket;
use std::io;
use std::time::{Duration, Instant};

pub(crate) const HEADER_LEN: usize = size_of::<u32>();

pub(crate) const CMD_LEN_BITS: u32 = 22;
const CMD_LEN_MASK: u32 = (1 << CMD_LEN_BITS) - 1;
pub const MAX_CMD_LEN: usize = CMD_LEN_MASK as usize;
pub const MAX_MINING_PAD_LEN: usize = 100;
pub(crate) const INITIAL_HEADER_KEY: u32 = 0xDC87_1829;
pub(crate) const NONCE_LEN: usize = 24;
const WORD_SIZE: usize = size_of::<u32>();
const NONCE_SEED_AT: usize = 7;
const NONCE_STEP: u32 = 42;
const SENDER_MASK: u32 = 0x5757_5757;

pub mod cmd {
    pub const HELLO_OR_PING: u8 = 1;
    pub(crate) const HANDSHAKE_RESPONSE: u8 = 2;
    pub const MINING: u8 = 5;
    pub const BULK: u8 = 6;
    pub const INFO: u8 = 7;
}

const RESERVED_SHIFT: u32 = CMD_LEN_BITS;
const RESERVED_MASK: u32 = 0x3;
const SIGNED_BIT: u32 = 24;
const ENCRYPTED_PUBKEY_BIT: u32 = 25;
const ENCRYPTED_CHANNEL_BIT: u32 = 26;
const PROTO_CMD_SHIFT: u32 = 27;
const PROTO_CMD_MASK: u32 = 0x1f;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FrameHeader {
    pub cmd_len: u32,
    pub reserved: u8,
    pub is_signed: bool,
    pub is_encrypted_pubkey: bool,
    pub is_encrypted_channel: bool,
    pub proto_cmd: u8,
}

impl FrameHeader {
    pub fn to_bytes(self) -> [u8; HEADER_LEN] {
        let v = (self.cmd_len & CMD_LEN_MASK)
            | ((u32::from(self.reserved) & RESERVED_MASK) << RESERVED_SHIFT)
            | (u32::from(self.is_signed) << SIGNED_BIT)
            | (u32::from(self.is_encrypted_pubkey) << ENCRYPTED_PUBKEY_BIT)
            | (u32::from(self.is_encrypted_channel) << ENCRYPTED_CHANNEL_BIT)
            | ((u32::from(self.proto_cmd) & PROTO_CMD_MASK) << PROTO_CMD_SHIFT);
        v.to_le_bytes()
    }

    pub fn from_bytes(b: [u8; HEADER_LEN]) -> Self {
        let v = u32::from_le_bytes(b);
        Self {
            cmd_len: v & CMD_LEN_MASK,
            reserved: ((v >> RESERVED_SHIFT) & RESERVED_MASK) as u8,
            is_signed: v & (1 << SIGNED_BIT) != 0,
            is_encrypted_pubkey: v & (1 << ENCRYPTED_PUBKEY_BIT) != 0,
            is_encrypted_channel: v & (1 << ENCRYPTED_CHANNEL_BIT) != 0,
            proto_cmd: ((v >> PROTO_CMD_SHIFT) & PROTO_CMD_MASK) as u8,
        }
    }
}

pub(crate) fn feedback(i: u32) -> u32 {
    let mut h: u32 = 0xb10c_feed;
    let mut k = i;
    k = k.wrapping_mul(0xcc9e_2d51);
    k = k.rotate_left(15);
    k = k.wrapping_mul(0x1b87_3593);
    h ^= k;
    h = h.rotate_left(13);
    h = h.wrapping_mul(5).wrapping_add(0xe654_6b64);
    h ^= 4;
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^= h >> 16;
    h
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderKeyRatchet {
    key: u32,
}

impl HeaderKeyRatchet {
    pub fn new(key: u32) -> Self {
        Self { key }
    }

    pub fn initial() -> Self {
        Self::new(INITIAL_HEADER_KEY)
    }

    pub fn mask(&mut self, h: FrameHeader) -> [u8; HEADER_LEN] {
        let v = u32::from_le_bytes(h.to_bytes()) ^ self.key;
        self.key = feedback(self.key);
        v.to_le_bytes()
    }

    pub fn unmask(&mut self, b: [u8; HEADER_LEN]) -> FrameHeader {
        let v = u32::from_le_bytes(b) ^ self.key;
        self.key = feedback(self.key);
        FrameHeader::from_bytes(v.to_le_bytes())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderKeys {
    pub client_to_server: u32,
    pub server_to_client: u32,
}

impl HeaderKeys {
    pub(crate) fn from_nk(nk: u32) -> Self {
        Self { client_to_server: feedback(nk), server_to_client: feedback(!nk) }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionNonces {
    pub client_receiver: [u8; NONCE_LEN],
    pub client_sender: [u8; NONCE_LEN],
}

impl SessionNonces {
    pub fn derive(nk: u32, session_sign_pk: &[u8; 32]) -> Self {
        let mut receiver = [0u8; NONCE_LEN];
        let mut sender = [0u8; NONCE_LEN];
        let seed: [u8; WORD_SIZE] = session_sign_pk[NONCE_SEED_AT..NONCE_SEED_AT + WORD_SIZE]
            .try_into()
            .expect("WORD_SIZE bytes");
        let mut n = nk.wrapping_sub(NONCE_STEP) ^ u32::from_le_bytes(seed);
        let sender_words = sender.as_chunks_mut::<WORD_SIZE>().0.iter_mut();
        for (rx, tx) in receiver.as_chunks_mut::<WORD_SIZE>().0.iter_mut().zip(sender_words) {
            let r = feedback(n.wrapping_sub(NONCE_STEP));
            *rx = r.to_le_bytes();
            *tx = (r ^ SENDER_MASK).to_le_bytes();
            n = !r;
        }
        Self { client_receiver: receiver, client_sender: sender }
    }
}

pub(crate) fn increment_nonce(nonce: &mut [u8; NONCE_LEN]) {
    for word in nonce.as_chunks_mut::<WORD_SIZE>().0 {
        let raised = u32::from_le_bytes(*word).wrapping_add(1);
        *word = raised.to_le_bytes();
        if raised != 0 {
            return;
        }
    }
}

/// How long a frame header may stay partially received before the peer is given up on.
pub(crate) const PARTIAL_HEADER_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameRead {
    Complete(FrameHeader, Vec<u8>),
    /// No byte of a header was waiting; the caller waits on its own schedule.
    Empty,
    Closed,
}

/// Reads the next frame from the socket: its header, unmasked by `unmask`, and the `cmd_len`
/// bytes that follow, which may stall for `body_idle` and take `body_total` in all. Once the
/// header's first byte has arrived the read waits for the rest, up to
/// `PARTIAL_HEADER_TIMEOUT`: a header or body that does not complete in time is an
/// `io::ErrorKind::TimedOut` error, and a peer that closes before it completes is an
/// `io::ErrorKind::UnexpectedEof` error. A header announcing more than `max_len` bytes is an
/// `io::ErrorKind::InvalidData` error, returned before the body is read or allocated.
pub fn read_next_frame(
    socket: &mut PolledSocket,
    unmask: impl FnOnce([u8; HEADER_LEN]) -> FrameHeader,
    max_len: usize,
    body_idle: Duration,
    body_total: Duration,
) -> io::Result<FrameRead> {
    let mut head = [0u8; HEADER_LEN];
    let got = match socket.read(&mut head)? {
        None => return Ok(FrameRead::Empty),
        Some(0) => return Ok(FrameRead::Closed),
        Some(n) => n,
    };
    socket.read_exact(&mut head[got..], PARTIAL_HEADER_TIMEOUT, PARTIAL_HEADER_TIMEOUT)?;
    let header = unmask(head);
    let len = header.cmd_len as usize;
    if len > max_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {len} bytes, over the {max_len} allowed"),
        ));
    }
    let body = socket.read_vec(len, body_idle, body_total)?;
    Ok(FrameRead::Complete(header, body))
}

/// Reads one whole frame by `deadline`: its header, unmasked by `unmask`, and the `cmd_len`
/// bytes that follow. A header announcing more than `max_len` bytes is an
/// `io::ErrorKind::InvalidData` error, returned before the body is read.
pub fn read_frame(
    socket: &mut PolledSocket,
    unmask: impl FnOnce([u8; HEADER_LEN]) -> FrameHeader,
    max_len: usize,
    deadline: Instant,
) -> io::Result<(FrameHeader, Vec<u8>)> {
    let left = || deadline.saturating_duration_since(Instant::now());
    let mut head = [0u8; HEADER_LEN];
    socket.read_exact(&mut head, left(), left())?;
    let header = unmask(head);
    let len = header.cmd_len as usize;
    if len > max_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {len} bytes, over the {max_len} allowed"),
        ));
    }
    let body = socket.read_vec(len, left(), left())?;
    Ok((header, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_packing_matches_c() {
        let cases: [(FrameHeader, &str, &str); 5] = [
            (
                FrameHeader {
                    cmd_len: 42,
                    is_signed: true,
                    is_encrypted_pubkey: true,
                    proto_cmd: 1,
                    ..Default::default()
                },
                "2a00000b",
                "031887d7",
            ),
            (
                FrameHeader {
                    cmd_len: 1,
                    is_encrypted_channel: true,
                    proto_cmd: 5,
                    ..Default::default()
                },
                "0100002c",
                "281887f0",
            ),
            (
                FrameHeader {
                    cmd_len: 4194303,
                    is_signed: true,
                    is_encrypted_pubkey: true,
                    is_encrypted_channel: true,
                    proto_cmd: 31,
                    reserved: 0,
                },
                "ffff3fff",
                "d6e7b823",
            ),
            (FrameHeader::default(), "00000000", "291887dc"),
            (
                FrameHeader {
                    cmd_len: 1234567,
                    is_encrypted_pubkey: true,
                    proto_cmd: 7,
                    ..Default::default()
                },
                "87d6123a",
                "aece95e6",
            ),
        ];
        for (h, raw, xored) in cases {
            assert_eq!(hex::encode(h.to_bytes()), raw, "raw encoding of {h:?}");
            assert_eq!(FrameHeader::from_bytes(h.to_bytes()), h, "roundtrip of {h:?}");
            let mut r = HeaderKeyRatchet::initial();
            assert_eq!(hex::encode(r.mask(h)), xored, "masked encoding of {h:?}");
        }
    }

    #[test]
    fn feedback_matches_c() {
        let vectors = [
            (0x0000_0000u32, 0x74a5_5cf6u32),
            (0x0000_0001, 0xab98_b5de),
            (0x0000_002a, 0xd545_aea2),
            (0xdc87_1829, 0x88e1_697d),
            (0xffff_ffff, 0x8541_e231),
            (0x1234_5678, 0x2bbb_e280),
            (0xb10c_feed, 0xd9dc_5e65),
        ];
        for (i, want) in vectors {
            assert_eq!(feedback(i), want, "feedback({i:#010x})");
        }
    }

    #[test]
    fn header_keys_from_nk_match_c() {
        let k = HeaderKeys::from_nk(0x9abc_def0);
        assert_eq!(k.client_to_server, 0x62aa_f25c);
        assert_eq!(k.server_to_client, 0x0cef_5178);
    }

    #[test]
    fn session_nonces_match_c() {
        let mut pk = [0u8; 32];
        for (i, b) in pk.iter_mut().enumerate() {
            *b = i as u8;
        }
        let n = SessionNonces::derive(0x9abc_def0, &pk);
        assert_eq!(
            hex::encode(n.client_receiver),
            "58d38abdfecc665c2cd520e1e970b81eb7f3cdd3f3bb1703"
        );
        assert_eq!(
            hex::encode(n.client_sender),
            "0f84ddeaa99b310b7b8277b6be27ef49e0a49a84a4ec4054"
        );
    }

    #[test]
    fn nonce_increment_matches_c() {
        let mut n = [0u8; NONCE_LEN];
        increment_nonce(&mut n);
        assert_eq!(hex::encode(n), "010000000000000000000000000000000000000000000000");

        let mut n = [0u8; NONCE_LEN];
        n[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        increment_nonce(&mut n);
        assert_eq!(hex::encode(n), "000000000100000000000000000000000000000000000000");

        let mut n = [0u8; NONCE_LEN];
        n[0..8].copy_from_slice(&[0xff; 8]);
        increment_nonce(&mut n);
        assert_eq!(hex::encode(n), "000000000000000001000000000000000000000000000000");

        let mut n = [0xffu8; NONCE_LEN];
        increment_nonce(&mut n);
        assert_eq!(hex::encode(n), "000000000000000000000000000000000000000000000000");
    }

    #[test]
    fn a_frame_split_across_reads_completes_and_a_close_between_frames_is_closed() {
        use std::io::Write as _;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let mut socket = PolledSocket::new(listener.accept().unwrap().0).unwrap();
        let limit = Duration::from_secs(5);
        let read = |socket: &mut PolledSocket| {
            read_next_frame(socket, FrameHeader::from_bytes, MAX_CMD_LEN, limit, limit).unwrap()
        };
        assert_eq!(read(&mut socket), FrameRead::Empty, "nothing sent yet");

        let header = FrameHeader { cmd_len: 2, proto_cmd: cmd::MINING, ..Default::default() };
        let wire = header.to_bytes();
        client.write_all(&wire[..2]).unwrap();
        let sender = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            client.write_all(&wire[2..]).unwrap();
            std::thread::sleep(Duration::from_millis(50));
            client.write_all(&[7, 8]).unwrap();
            client
        });
        socket.wait(Some(limit)).unwrap();
        assert_eq!(read(&mut socket), FrameRead::Complete(header, vec![7, 8]));

        drop(sender.join().unwrap());
        socket.wait(Some(limit)).unwrap();
        assert_eq!(read(&mut socket), FrameRead::Closed);
    }

    #[test]
    fn ratchet_is_symmetric() {
        let mut tx = HeaderKeyRatchet::new(0x1234_5678);
        let mut rx = HeaderKeyRatchet::new(0x1234_5678);
        for i in 0..64u32 {
            let h = FrameHeader {
                cmd_len: i * 7,
                is_encrypted_channel: true,
                proto_cmd: (i % 32) as u8,
                ..Default::default()
            };
            assert_eq!(rx.unmask(tx.mask(h)), h);
        }
        let last = FrameHeader { cmd_len: 4095, proto_cmd: 31, ..Default::default() };
        assert_eq!(rx.unmask(tx.mask(last)), last);
    }
}
