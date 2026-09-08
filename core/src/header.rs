use blake2::Blake2b;
use blake2::digest::Digest as _;
use blake2::digest::consts::U32;
use sha2::Sha256;

pub const HEADER_V2_SIZE: usize = 164;
pub const V2_FLAG: u32 = 0x8000_0000;
pub const FLAG_USE_TIME_OFFSET: u8 = 4;
pub const FLAG_PROFILE_MASK: u8 = 3;

pub const ASIC_INPUT_LEN: [usize; 4] = [80, 80, 128, 160];
const ASIC_INPUT_LEADING_ZEROS: [usize; 4] = [0, 0, 48, 80];

pub const H1_PREIMAGE_SIZE: usize = 119;
pub const H2_PREIMAGE_SIZE: usize = 96;
const H2_MM_RHS_OFFSET: usize = 64;

pub const WORK_ROOT_LEAF_SIZE: usize = 52;
pub const WORK_ROOT_H2_OFFSET: usize = 4;
pub const COINB1_LEADING_ZEROS: usize = WORK_ROOT_H2_OFFSET - 1;
const WORK_ROOT_EXTRANONCE_OFFSET: usize = 36;

const PREVBLOCK_HIDDEN_CLEARED_BYTES: usize = 6;

pub type U256 = [u8; 32];
pub type U128 = [u8; 16];

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct HeaderV2 {
    pub version: i32,
    pub prev_block: U256,
    pub merkle_root: U256,
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
    pub nonce2: u32,
    pub nonce3: u32,
    pub extranonce: U128,
    pub time_offset: u32,
    pub txcount: u16,
    pub flags: u8,
    pub xor_key_mask_clear_bits: u8,
    pub xor_key: U128,
    pub height: i32,
    pub mm_rhs: U256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashComponents {
    pub xor_key_hash: [u8; 32],
    pub prevblock_hidden: [u8; 32],
    pub h1: [u8; 32],
    pub h2: [u8; 32],
    pub hash1: [u8; 32],
    pub asic_profile: u8,
    pub asic_input: Vec<u8>,
    pub hash2: [u8; 32],
    pub mask: [u8; 32],
    pub result: [u8; 32],
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn tagged_sha256(tag: &str, data: &[u8]) -> [u8; 32] {
    let t = sha256(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    h.update(data);
    h.finalize().into()
}

pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut h = Blake2b::<U32>::new();
    h.update(data);
    h.finalize().into()
}

impl HeaderV2 {
    pub fn time_on_wire(&self) -> u32 {
        if self.flags & FLAG_USE_TIME_OFFSET == 0 {
            self.time
        } else {
            self.time.wrapping_sub(self.time_offset)
        }
    }

    pub fn asic_profile(&self) -> u8 {
        self.flags & FLAG_PROFILE_MASK
    }

    pub fn serialize(&self) -> [u8; HEADER_V2_SIZE] {
        let mut out = [0u8; HEADER_V2_SIZE];
        let mut w = Writer::new(&mut out);
        w.u32(V2_FLAG | (self.version as u32 & !V2_FLAG));
        w.bytes(&self.prev_block);
        w.bytes(&self.merkle_root);
        w.u32(self.time_on_wire());
        w.u32(self.bits);
        w.u32(self.nonce);
        w.u32(self.nonce2);
        w.u32(self.nonce3);
        w.bytes(&self.extranonce);
        w.u32(self.time_offset);
        w.u16(self.txcount);
        w.u8(self.flags);
        w.u8(self.xor_key_mask_clear_bits);
        w.bytes(&self.xor_key);
        w.i32(self.height);
        w.bytes(&self.mm_rhs);
        debug_assert_eq!(w.pos, HEADER_V2_SIZE);
        out
    }

    pub fn deserialize(b: &[u8]) -> Option<Self> {
        if b.len() != HEADER_V2_SIZE {
            return None;
        }
        let mut r = Reader::new(b);
        let v = r.u32();
        if v & V2_FLAG == 0 {
            return None;
        }
        let mut h = HeaderV2 {
            version: (v & !V2_FLAG) as i32,
            prev_block: r.arr(),
            merkle_root: r.arr(),
            time: r.u32(),
            bits: r.u32(),
            nonce: r.u32(),
            nonce2: r.u32(),
            nonce3: r.u32(),
            extranonce: r.arr(),
            time_offset: r.u32(),
            txcount: r.u16(),
            flags: r.u8(),
            xor_key_mask_clear_bits: r.u8(),
            xor_key: r.arr(),
            height: r.u32() as i32,
            mm_rhs: r.arr(),
        };
        if h.flags & FLAG_USE_TIME_OFFSET != 0 {
            h.time = h.time.wrapping_add(h.time_offset);
        }
        Some(h)
    }

    pub fn asic_input_with(&self, hash1: &[u8; 32], h2: &[u8; 32]) -> Vec<u8> {
        let profile = self.asic_profile();
        let mut ss = Vec::with_capacity(ASIC_INPUT_LEN[profile as usize]);
        match profile {
            1 => {
                ss.extend_from_slice(&self.nonce.to_le_bytes());
                ss.extend_from_slice(&self.nonce2.to_le_bytes());
                ss.extend_from_slice(&self.nonce3.to_le_bytes());
                ss.extend_from_slice(&self.time_offset.to_le_bytes());
                ss.extend_from_slice(hash1);
                ss.extend_from_slice(h2);
            }
            p => {
                ss.resize(ASIC_INPUT_LEADING_ZEROS[p as usize], 0);
                if p == 0 {
                    ss.extend_from_slice(&prevblock_hidden(&self.prev_block));
                } else {
                    ss.extend_from_slice(h2);
                }
                ss.extend_from_slice(&self.nonce.to_le_bytes());
                ss.extend_from_slice(&self.nonce2.to_le_bytes());
                ss.extend_from_slice(&self.time_offset.to_le_bytes());
                ss.extend_from_slice(&self.nonce3.to_le_bytes());
                ss.extend_from_slice(hash1);
            }
        }
        debug_assert_eq!(ss.len(), ASIC_INPUT_LEN[profile as usize]);
        ss
    }

    pub fn precompute(&self) -> Precomputed {
        let xor_key_hash = tagged_sha256("Bitcoin block hash PoW XOR key", &self.xor_key);
        self.precompute_with_key_hash(xor_key_hash)
    }

    pub fn precompute_with_key_hash(&self, xor_key_hash: [u8; 32]) -> Precomputed {
        let mut prev_display = self.prev_block;
        prev_display.reverse();

        let mut h1d = Vec::with_capacity(H1_PREIMAGE_SIZE);
        h1d.extend_from_slice(&(self.version as u32 | V2_FLAG).to_le_bytes());
        h1d.extend_from_slice(&prev_display);
        h1d.extend_from_slice(&self.height.to_le_bytes());
        h1d.extend_from_slice(&self.merkle_root);
        h1d.extend_from_slice(&self.time_on_wire().to_le_bytes());
        h1d.push(0);
        h1d.extend_from_slice(&self.bits.to_le_bytes());
        h1d.extend_from_slice(&(self.txcount as u32).to_le_bytes());
        h1d.push(self.flags);
        h1d.push(self.xor_key_mask_clear_bits);
        h1d.extend_from_slice(&xor_key_hash);
        debug_assert_eq!(h1d.len(), H1_PREIMAGE_SIZE);
        let h1 = tagged_sha256("Bitcoin block header 1", &h1d);

        let mut h2d = [0u8; H2_PREIMAGE_SIZE];
        h2d[..h1.len()].copy_from_slice(&h1);
        h2d[H2_MM_RHS_OFFSET..].copy_from_slice(&self.mm_rhs);
        let h2 = tagged_sha256("Merge-mining hook", &h2d);

        let mut leaf = [0u8; WORK_ROOT_LEAF_SIZE];
        leaf[WORK_ROOT_H2_OFFSET..WORK_ROOT_EXTRANONCE_OFFSET].copy_from_slice(&h2);
        leaf[WORK_ROOT_EXTRANONCE_OFFSET..].copy_from_slice(&self.extranonce);
        let hash1 = blake2b_256(&leaf);

        let mask = xor_mask(&self.xor_key, self.xor_key_mask_clear_bits);

        Precomputed { xor_key_hash, h1, h2, hash1, mask }
    }

    pub fn hash_components(&self) -> HashComponents {
        let pre = self.precompute();
        let asic_input = self.asic_input_with(&pre.hash1, &pre.h2);
        let hash2 = blake2b_256(&asic_input);
        let mut result = hash2;
        for (r, m) in result.iter_mut().zip(pre.mask) {
            *r ^= m;
        }
        HashComponents {
            xor_key_hash: pre.xor_key_hash,
            prevblock_hidden: prevblock_hidden(&self.prev_block),
            h1: pre.h1,
            h2: pre.h2,
            hash1: pre.hash1,
            asic_profile: self.asic_profile(),
            asic_input,
            hash2,
            mask: pre.mask,
            result,
        }
    }

    pub fn pow_hash(&self) -> U256 {
        let mut r = self.hash_components().result;
        r.reverse();
        r
    }

    pub fn pow_hash_hex(&self) -> String {
        hex::encode(self.hash_components().result)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Precomputed {
    pub xor_key_hash: [u8; 32],
    pub h1: [u8; 32],
    pub h2: [u8; 32],
    pub hash1: [u8; 32],
    pub mask: [u8; 32],
}

pub fn prevblock_hidden(prev_block: &U256) -> [u8; 32] {
    let mut display = *prev_block;
    display.reverse();
    let mut out = tagged_sha256("Bitcoin prevblock header, hashed", &display);
    out[..PREVBLOCK_HIDDEN_CLEARED_BYTES].fill(0);
    out
}

pub fn xor_mask(xor_key: &U128, clear_bits: u8) -> [u8; 32] {
    if xor_key.iter().all(|&b| b == 0) {
        return [0u8; 32];
    }
    let mut m = tagged_sha256("Bitcoin block hash PoW XOR mask", xor_key);
    let bits_per_byte = u8::BITS as u8;
    let clear_bytes = usize::from(clear_bits / bits_per_byte);
    for b in m.iter_mut().take(clear_bytes) {
        *b = 0;
    }
    if let Some(b) = m.get_mut(clear_bytes) {
        *b &= u8::MAX >> (clear_bits % bits_per_byte);
    }
    m
}

pub fn u256_from_display_hex(s: &str) -> Option<U256> {
    let mut v: U256 = hex::decode(s).ok()?.try_into().ok()?;
    v.reverse();
    Some(v)
}

pub fn u128_from_display_hex(s: &str) -> Option<U128> {
    let mut v: U128 = hex::decode(s).ok()?.try_into().ok()?;
    v.reverse();
    Some(v)
}

pub fn display_hex(le: &[u8]) -> String {
    let mut v = le.to_vec();
    v.reverse();
    hex::encode(v)
}

struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Writer { buf, pos: 0 }
    }
    fn bytes(&mut self, b: &[u8]) {
        self.buf[self.pos..self.pos + b.len()].copy_from_slice(b);
        self.pos += b.len();
    }
    fn u8(&mut self, v: u8) {
        self.bytes(&[v]);
    }
    fn u16(&mut self, v: u16) {
        self.bytes(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.bytes(&v.to_le_bytes());
    }
    fn i32(&mut self, v: i32) {
        self.bytes(&v.to_le_bytes());
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> &'a [u8] {
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        s
    }
    fn arr<const N: usize>(&mut self) -> [u8; N] {
        self.take(N).try_into().unwrap()
    }
    fn u8(&mut self) -> u8 {
        self.take(1)[0]
    }
    fn u16(&mut self) -> u16 {
        u16::from_le_bytes(self.arr())
    }
    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.arr())
    }
}
