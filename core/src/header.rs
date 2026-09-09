use crate::cursor::Cursor;
use blake2::Blake2b;
use blake2::digest::Digest as _;
use blake2::digest::consts::U32;
use bytes::BufMut as _;
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
        let mut w = &mut out[..];
        w.put_u32_le(V2_FLAG | (self.version as u32 & !V2_FLAG));
        w.put_slice(&self.prev_block);
        w.put_slice(&self.merkle_root);
        w.put_u32_le(self.time_on_wire());
        w.put_u32_le(self.bits);
        w.put_u32_le(self.nonce);
        w.put_u32_le(self.nonce2);
        w.put_u32_le(self.nonce3);
        w.put_slice(&self.extranonce);
        w.put_u32_le(self.time_offset);
        w.put_u16_le(self.txcount);
        w.put_u8(self.flags);
        w.put_u8(self.xor_key_mask_clear_bits);
        w.put_slice(&self.xor_key);
        w.put_i32_le(self.height);
        w.put_slice(&self.mm_rhs);
        assert!(w.is_empty(), "the fields above total HEADER_V2_SIZE bytes");
        out
    }

    pub fn deserialize(b: &[u8]) -> Option<Self> {
        if b.len() != HEADER_V2_SIZE {
            return None;
        }
        let mut r = Cursor::new(b);
        let v = r.u32("version").ok()?;
        if v & V2_FLAG == 0 {
            return None;
        }
        let mut h = Self {
            version: (v & !V2_FLAG) as i32,
            prev_block: r.arr("prev block").ok()?,
            merkle_root: r.arr("merkle root").ok()?,
            time: r.u32("time").ok()?,
            bits: r.u32("bits").ok()?,
            nonce: r.u32("nonce").ok()?,
            nonce2: r.u32("nonce2").ok()?,
            nonce3: r.u32("nonce3").ok()?,
            extranonce: r.arr("extranonce").ok()?,
            time_offset: r.u32("time offset").ok()?,
            txcount: r.u16("txcount").ok()?,
            flags: r.u8("flags").ok()?,
            xor_key_mask_clear_bits: r.u8("xor key mask clear bits").ok()?,
            xor_key: r.arr("xor key").ok()?,
            height: r.u32("height").ok()? as i32,
            mm_rhs: r.arr("mm rhs").ok()?,
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
                ss.put_u32_le(self.nonce);
                ss.put_u32_le(self.nonce2);
                ss.put_u32_le(self.nonce3);
                ss.put_u32_le(self.time_offset);
                ss.put_slice(hash1);
                ss.put_slice(h2);
            }
            p => {
                ss.resize(ASIC_INPUT_LEADING_ZEROS[p as usize], 0);
                if p == 0 {
                    ss.put_slice(&prevblock_hidden(&self.prev_block));
                } else {
                    ss.put_slice(h2);
                }
                ss.put_u32_le(self.nonce);
                ss.put_u32_le(self.nonce2);
                ss.put_u32_le(self.time_offset);
                ss.put_u32_le(self.nonce3);
                ss.put_slice(hash1);
            }
        }
        debug_assert_eq!(ss.len(), ASIC_INPUT_LEN[profile as usize]);
        ss
    }

    pub fn precompute(&self) -> Precomputed {
        self.precompute_with_key_hash(xor_key_hash(&self.xor_key))
    }

    pub fn precompute_with_key_hash(&self, xor_key_hash: [u8; 32]) -> Precomputed {
        let prev_display = crate::bitcoin::reversed(&self.prev_block);

        let mut h1d = [0u8; H1_PREIMAGE_SIZE];
        let mut w = &mut h1d[..];
        w.put_u32_le(self.version as u32 | V2_FLAG);
        w.put_slice(&prev_display);
        w.put_i32_le(self.height);
        w.put_slice(&self.merkle_root);
        w.put_u32_le(self.time_on_wire());
        w.put_u8(0);
        w.put_u32_le(self.bits);
        w.put_u32_le(u32::from(self.txcount));
        w.put_u8(self.flags);
        w.put_u8(self.xor_key_mask_clear_bits);
        w.put_slice(&xor_key_hash);
        debug_assert!(w.is_empty(), "the fields above total H1_PREIMAGE_SIZE bytes");
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

        Precomputed { h2, hash1, mask }
    }

    pub fn pow_and_block_hash(&self) -> ([u8; 32], [u8; 32]) {
        let pre = self.precompute();
        let pow = blake2b_256(&self.asic_input_with(&pre.hash1, &pre.h2));
        let mut block = pow;
        for (b, m) in block.iter_mut().zip(pre.mask) {
            *b ^= m;
        }
        (pow, block)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Precomputed {
    pub h2: [u8; 32],
    pub hash1: [u8; 32],
    pub mask: [u8; 32],
}

pub fn xor_key_hash(xor_key: &U128) -> [u8; 32] {
    tagged_sha256("Bitcoin block hash PoW XOR key", xor_key)
}

pub fn prevblock_hidden(prev_block: &U256) -> [u8; 32] {
    let display = crate::bitcoin::reversed(prev_block);
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
    let v: U256 = hex::decode(s).ok()?.try_into().ok()?;
    Some(crate::bitcoin::reversed(&v))
}

pub fn u256_to_display_hex(v: &U256) -> String {
    hex::encode(crate::bitcoin::reversed(v))
}
