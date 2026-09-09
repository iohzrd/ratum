pub const HEADER_LEN: usize = size_of::<u32>();

const CMD_LEN_BITS: u32 = 22;
pub const MAX_CMD_LEN: u32 = (1 << CMD_LEN_BITS) - 1;
pub const MAX_CMD_DATA_SIZE: u32 = 1 << CMD_LEN_BITS;
pub const INITIAL_HELLO_KEY: u32 = 0xDC87_1829;
pub const NONCE_LEN: usize = 24;
const WORD: usize = size_of::<u32>();
const NONCE_SEED_AT: usize = 7;
const NONCE_STEP: u32 = 42;
const SENDER_MASK: u32 = 0x5757_5757;
pub const STRUCT_END: u8 = 0xFE;

pub mod cmd {
    pub const HELLO_OR_PING: u8 = 1;
    pub const HANDSHAKE_RESPONSE: u8 = 2;
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
pub struct Header {
    pub cmd_len: u32,
    pub reserved: u8,
    pub is_signed: bool,
    pub is_encrypted_pubkey: bool,
    pub is_encrypted_channel: bool,
    pub proto_cmd: u8,
}

impl Header {
    pub fn to_bytes(self) -> [u8; HEADER_LEN] {
        let v = (self.cmd_len & MAX_CMD_LEN)
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
            cmd_len: v & MAX_CMD_LEN,
            reserved: ((v >> RESERVED_SHIFT) & RESERVED_MASK) as u8,
            is_signed: v & (1 << SIGNED_BIT) != 0,
            is_encrypted_pubkey: v & (1 << ENCRYPTED_PUBKEY_BIT) != 0,
            is_encrypted_channel: v & (1 << ENCRYPTED_CHANNEL_BIT) != 0,
            proto_cmd: ((v >> PROTO_CMD_SHIFT) & PROTO_CMD_MASK) as u8,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyRatchet {
    key: u32,
}

impl KeyRatchet {
    pub fn new(key: u32) -> Self {
        Self { key }
    }

    pub fn hello() -> Self {
        Self::new(INITIAL_HELLO_KEY)
    }

    pub fn mask(&mut self, h: Header) -> [u8; HEADER_LEN] {
        let v = u32::from_le_bytes(h.to_bytes()) ^ self.key;
        self.key = feedback(self.key);
        v.to_le_bytes()
    }

    pub fn unmask(&mut self, b: [u8; HEADER_LEN]) -> Header {
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
    pub fn from_nk(nk: u32) -> Self {
        Self { client_to_server: feedback(nk), server_to_client: feedback(!nk) }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionNonces {
    pub client_receiver: [u8; NONCE_LEN],
    pub client_sender: [u8; NONCE_LEN],
}

impl SessionNonces {
    pub fn derive(nk: u32, session_pk_ed25519: &[u8; 32]) -> Self {
        let mut receiver = [0u8; NONCE_LEN];
        let mut sender = [0u8; NONCE_LEN];
        let seed: [u8; WORD] =
            session_pk_ed25519[NONCE_SEED_AT..NONCE_SEED_AT + WORD].try_into().expect("WORD bytes");
        let mut n = nk.wrapping_sub(NONCE_STEP) ^ u32::from_le_bytes(seed);
        let sender_words = sender.as_chunks_mut::<WORD>().0.iter_mut();
        for (rx, tx) in receiver.as_chunks_mut::<WORD>().0.iter_mut().zip(sender_words) {
            let r = feedback(n.wrapping_sub(NONCE_STEP));
            *rx = r.to_le_bytes();
            *tx = (r ^ SENDER_MASK).to_le_bytes();
            n = !r;
        }
        Self { client_receiver: receiver, client_sender: sender }
    }
}

pub fn increment_nonce(nonce: &mut [u8; NONCE_LEN]) {
    for word in nonce.as_chunks_mut::<WORD>().0 {
        let raised = u32::from_le_bytes(*word).wrapping_add(1);
        *word = raised.to_le_bytes();
        if raised != 0 {
            return;
        }
    }
}
