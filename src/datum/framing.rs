/// The largest value the header's 22-bit length field can hold.
pub const MAX_CMD_LEN: u32 = (1 << 22) - 1;
/// The gateway's `DATUM_PROTOCOL_MAX_CMD_DATA_SIZE`, one larger than the largest length the
/// 22-bit field holds.
pub const MAX_CMD_DATA_SIZE: u32 = 1 << 22;
pub const INITIAL_HELLO_KEY: u32 = 0xDC87_1829;
pub const NONCE_LEN: usize = 24;
/// The byte the gateway writes as a structure terminator. In the hello it follows the user
/// agent's NUL and precedes `nk` and the pad; in the config it follows a 0x00.
pub const STRUCT_END: u8 = 0xFE;

pub mod cmd {
    pub const HELLO_OR_PING: u8 = 1;
    pub const HANDSHAKE_RESPONSE: u8 = 2;
    pub const MINING: u8 = 5;
    pub const INFO: u8 = 7;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Header {
    pub cmd_len: u32,
    pub reserved: u8,
    pub is_signed: bool,
    pub is_encrypted_pubkey: bool,
    pub is_encrypted_channel: bool,
    pub proto_cmd: u8,
}

impl Header {
    pub fn to_bytes(self) -> [u8; 4] {
        let v = (self.cmd_len & MAX_CMD_LEN)
            | ((self.reserved as u32 & 0x3) << 22)
            | ((self.is_signed as u32) << 24)
            | ((self.is_encrypted_pubkey as u32) << 25)
            | ((self.is_encrypted_channel as u32) << 26)
            | ((self.proto_cmd as u32 & 0x1f) << 27);
        v.to_le_bytes()
    }

    pub fn from_bytes(b: [u8; 4]) -> Self {
        let v = u32::from_le_bytes(b);
        Header {
            cmd_len: v & MAX_CMD_LEN,
            reserved: ((v >> 22) & 0x3) as u8,
            is_signed: v & (1 << 24) != 0,
            is_encrypted_pubkey: v & (1 << 25) != 0,
            is_encrypted_channel: v & (1 << 26) != 0,
            proto_cmd: ((v >> 27) & 0x1f) as u8,
        }
    }
}

pub fn feedback(i: u32) -> u32 {
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

/// The gateway's "header feedback" XOR key for frame headers: `datum_header_xor_feedback`
/// advances it once per frame and `datum_xor_header_key` applies it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyRatchet {
    key: u32,
}

impl KeyRatchet {
    pub fn new(key: u32) -> Self {
        KeyRatchet { key }
    }

    pub fn hello() -> Self {
        KeyRatchet::new(INITIAL_HELLO_KEY)
    }

    pub fn key(self) -> u32 {
        self.key
    }

    /// XOR the header with the current key, then advance the key.
    pub fn mask(&mut self, h: Header) -> [u8; 4] {
        let v = u32::from_le_bytes(h.to_bytes()) ^ self.key;
        self.key = feedback(self.key);
        v.to_le_bytes()
    }

    pub fn unmask(&mut self, b: [u8; 4]) -> Header {
        let v = u32::from_le_bytes(b) ^ self.key;
        self.key = feedback(self.key);
        Header::from_bytes(v.to_le_bytes())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderKeys {
    pub client_to_server: u32,
    pub server_to_client: u32,
}

impl HeaderKeys {
    /// The gateway's sending and receiving keys, named here by absolute direction
    /// (`datum_protocol.c`, where they are set from `nk` and `~nk`).
    pub fn from_nk(nk: u32) -> Self {
        HeaderKeys { client_to_server: feedback(nk), server_to_client: feedback(!nk) }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionNonces {
    pub client_receiver: [u8; NONCE_LEN],
    pub client_sender: [u8; NONCE_LEN],
}

impl SessionNonces {
    /// The offsets and the 42 are the gateway's, transcribed rather than derived; the
    /// `session_nonces_match_c` test below checks this loop against the C-derived vectors.
    pub fn derive(nk: u32, session_pk_ed25519: &[u8; 32]) -> Self {
        let mut receiver = [0u8; NONCE_LEN];
        let mut sender = [0u8; NONCE_LEN];
        let mut n = nk.wrapping_sub(42);
        n ^= u32::from_le_bytes(session_pk_ed25519[7..11].try_into().unwrap());
        for j in (0..NONCE_LEN).step_by(4) {
            let r = feedback(n.wrapping_sub(42));
            receiver[j..j + 4].copy_from_slice(&r.to_le_bytes());
            sender[j..j + 4].copy_from_slice(&(r ^ 0x5757_5757).to_le_bytes());
            n = !r;
        }
        SessionNonces { client_receiver: receiver, client_sender: sender }
    }
}

/// Counts up in 32-bit words, least significant word first, carrying only when one wraps to
/// zero; this matches the gateway's host-order `uint32_t` increment on little-endian hosts.
pub fn increment_nonce(nonce: &mut [u8; NONCE_LEN]) {
    for j in (0..NONCE_LEN).step_by(4) {
        let w = u32::from_le_bytes(nonce[j..j + 4].try_into().unwrap()).wrapping_add(1);
        nonce[j..j + 4].copy_from_slice(&w.to_le_bytes());
        if w != 0 {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_packing_matches_c() {
        let cases: [(Header, &str, &str); 5] = [
            (
                Header {
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
                Header {
                    cmd_len: 1,
                    is_encrypted_channel: true,
                    proto_cmd: 5,
                    ..Default::default()
                },
                "0100002c",
                "281887f0",
            ),
            (
                Header {
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
            (Header::default(), "00000000", "291887dc"),
            (
                Header {
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
            assert_eq!(Header::from_bytes(h.to_bytes()), h, "roundtrip of {h:?}");
            let mut r = KeyRatchet::hello();
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
    fn ratchet_is_symmetric() {
        let mut tx = KeyRatchet::new(0x1234_5678);
        let mut rx = KeyRatchet::new(0x1234_5678);
        for i in 0..64u32 {
            let h = Header {
                cmd_len: i * 7,
                is_encrypted_channel: true,
                proto_cmd: (i % 32) as u8,
                ..Default::default()
            };
            assert_eq!(rx.unmask(tx.mask(h)), h);
        }
        assert_eq!(tx.key(), rx.key());
    }
}
