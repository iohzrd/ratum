//! The version 2 (BLAKE2b) block header. `serialize` and `deserialize` are its 164-byte wire form;
//! `hash_stages` takes it through the two tagged SHA-256 stages and the BLAKE2b work root to the
//! input the hardware hashes, and `pow_hashes` on to the proof-of-work hash and the block hash the
//! XOR key mask separates it from.

use crate::reader::ByteReader;
use blake2::Blake2b;
use blake2::digest::Digest as _;
use blake2::digest::consts::U32;
use bytes::BufMut as _;
use sha2::Sha256;

pub const HEADER_V2_SIZE: usize = 164;
pub const V2_FLAG: u32 = 0x8000_0000;
pub const FLAG_USE_TIME_OFFSET: u8 = 4;
pub(crate) const FLAG_PROFILE_MASK: u8 = 3;

pub const ASIC_INPUT_LEN: [usize; 4] = [80, 80, 128, 160];
const ASIC_INPUT_LEADING_ZEROS: [usize; 4] = [0, 0, 48, 80];

/// One of the two little-endian words a sia nonce or sia time field packs.
pub const SIA_WORD_LEN: usize = size_of::<u32>();
/// The sia nonce and sia time fields, of two words each.
pub const SIA_WORDS_LEN: usize = 2 * SIA_WORD_LEN;

/// The body profiles 0, 2 and 3 share, which is the whole input under profile 0.
pub const ASIC_INPUT_BODY_LEN: usize = ASIC_INPUT_LEN[0];
const ASIC_INPUT_HEAD_LEN: usize = 32;
/// Where the nonce sits in `asic_input_body`, which is where a miner splices the one it
/// searches.
pub const ASIC_INPUT_NONCE_AT: usize = ASIC_INPUT_HEAD_LEN;
const ASIC_INPUT_NTIME_AT: usize = ASIC_INPUT_NONCE_AT + SIA_WORDS_LEN;
const ASIC_INPUT_WORK_ROOT_AT: usize = ASIC_INPUT_NTIME_AT + SIA_WORDS_LEN;

pub(crate) const H1_PREIMAGE_SIZE: usize = 119;
pub(crate) const H2_PREIMAGE_SIZE: usize = 96;
const H2_MM_RHS_OFFSET: usize = 64;

pub const WORK_ROOT_LEAF_SIZE: usize = 52;
pub const WORK_ROOT_H2_OFFSET: usize = 4;
pub const COINB1_LEADING_ZEROS: usize = WORK_ROOT_H2_OFFSET - 1;
const WORK_ROOT_EXTRANONCE_OFFSET: usize = 36;

const PREVBLOCK_HIDDEN_CLEARED_BYTES: usize = 6;

pub type XorKey = [u8; 16];

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct BlockHeaderV2 {
    pub version: i32,
    pub prev_block: [u8; 32],
    pub merkle_root: [u8; 32],
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
    pub nonce2: u32,
    pub nonce3: u32,
    pub extranonce: [u8; 16],
    pub time_offset: u32,
    pub txcount: u16,
    pub flags: u8,
    pub xor_key_mask_clear_bits: u8,
    pub xor_key: XorKey,
    pub height: i32,
    pub mm_rhs: [u8; 32],
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub(crate) fn tagged_sha256(tag: &str, data: &[u8]) -> [u8; 32] {
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

/// The bytes the hardware hashes under profile 0, and the body profiles 2 and 3 place after
/// their leading zeros: a 32-byte head, the sia nonce and time fields the header's four nonce
/// words pack into, and the work root. The head is the hidden previous block hash under
/// profile 0 and H2 under profiles 2 and 3.
///
/// This is the one encoding of that layout: `asic_input_with` builds every profile but 1 from
/// it, and a miner holding the stratum fields rather than a header calls it directly.
pub fn asic_input_body(
    head: &[u8; ASIC_INPUT_HEAD_LEN],
    sia_nonce: &[u8; SIA_WORDS_LEN],
    sia_ntime: &[u8; SIA_WORDS_LEN],
    work_root: &[u8; 32],
) -> [u8; ASIC_INPUT_BODY_LEN] {
    let mut out = [0u8; ASIC_INPUT_BODY_LEN];
    out[..ASIC_INPUT_NONCE_AT].copy_from_slice(head);
    out[ASIC_INPUT_NONCE_AT..ASIC_INPUT_NTIME_AT].copy_from_slice(sia_nonce);
    out[ASIC_INPUT_NTIME_AT..ASIC_INPUT_WORK_ROOT_AT].copy_from_slice(sia_ntime);
    out[ASIC_INPUT_WORK_ROOT_AT..].copy_from_slice(work_root);
    out
}

/// The two little-endian words `asic_input_body` reads a sia field as.
pub fn sia_words(low: u32, high: u32) -> [u8; SIA_WORDS_LEN] {
    let mut f = [0u8; SIA_WORDS_LEN];
    let (l, h) = f.split_at_mut(SIA_WORD_LEN);
    l.copy_from_slice(&low.to_le_bytes());
    h.copy_from_slice(&high.to_le_bytes());
    f
}

impl BlockHeaderV2 {
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
        let mut r = ByteReader::new(b);
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

    pub fn asic_input_with(&self, work_root: &[u8; 32], h2: &[u8; 32]) -> Vec<u8> {
        let profile = self.asic_profile();
        let mut ss = Vec::with_capacity(ASIC_INPUT_LEN[profile as usize]);
        match profile {
            1 => {
                ss.put_u32_le(self.nonce);
                ss.put_u32_le(self.nonce2);
                ss.put_u32_le(self.nonce3);
                ss.put_u32_le(self.time_offset);
                ss.put_slice(work_root);
                ss.put_slice(h2);
            }
            p => {
                ss.resize(ASIC_INPUT_LEADING_ZEROS[p as usize], 0);
                let head = if p == 0 { prevblock_hidden(&self.prev_block) } else { *h2 };
                ss.put_slice(&asic_input_body(
                    &head,
                    &sia_words(self.nonce, self.nonce2),
                    &sia_words(self.time_offset, self.nonce3),
                    work_root,
                ));
            }
        }
        debug_assert_eq!(ss.len(), ASIC_INPUT_LEN[profile as usize]);
        ss
    }

    pub fn hash_stages(&self) -> HashStages {
        self.hash_stages_with_key_hash(xor_key_hash(&self.xor_key))
    }

    pub fn hash_stages_with_key_hash(&self, xor_key_hash: [u8; 32]) -> HashStages {
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

        HashStages {
            h1,
            h2,
            work_root: work_root(&h2, &self.extranonce),
            xor_key_mask: xor_key_mask(&self.xor_key, self.xor_key_mask_clear_bits),
        }
    }

    /// The BLAKE2b hash of the ASIC input `stages` give, before the XOR mask is applied.
    pub fn raw_pow_hash(&self, stages: &HashStages) -> [u8; 32] {
        blake2b_256(&self.asic_input_with(&stages.work_root, &stages.h2))
    }

    pub fn pow_hashes(&self) -> PowHashes {
        let stages = self.hash_stages();
        let raw_pow_hash = self.raw_pow_hash(&stages);
        let mut block_hash = raw_pow_hash;
        for (b, m) in block_hash.iter_mut().zip(stages.xor_key_mask) {
            *b ^= m;
        }
        PowHashes { raw_pow_hash, block_hash }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowHashes {
    pub raw_pow_hash: [u8; 32],
    pub block_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HashStages {
    pub h1: [u8; 32],
    pub h2: [u8; 32],
    pub work_root: [u8; 32],
    pub xor_key_mask: [u8; 32],
}

/// The BLAKE2b work root the ASIC input commits to: H2 and the header's 16-byte extranonce
/// at their offsets in a `WORK_ROOT_LEAF_SIZE` leaf, the bytes before H2 left zero.
///
/// This is the one place the leaf is laid out. A miner holding the stratum fields rather
/// than a header reaches the same bytes through `work_root_from_stratum`, so neither side
/// can be moved without the other.
pub fn work_root(h2: &[u8; 32], extranonce: &[u8; 16]) -> [u8; 32] {
    let mut leaf = [0u8; WORK_ROOT_LEAF_SIZE];
    leaf[WORK_ROOT_H2_OFFSET..WORK_ROOT_EXTRANONCE_OFFSET].copy_from_slice(h2);
    leaf[WORK_ROOT_EXTRANONCE_OFFSET..].copy_from_slice(extranonce);
    blake2b_256(&leaf)
}

/// The zero bytes a stratum miner puts before `coinb1` to reach `WORK_ROOT_H2_OFFSET`: the
/// gateway writes `COINB1_LEADING_ZEROS` of them into coinb1 itself and the miner supplies
/// the rest. Splitting the offset this way is what a stratum coinbase looks like, so both
/// halves are named here rather than one of them living in the miner.
pub(crate) const STRATUM_LEAF_PREFIX_LEN: usize = WORK_ROOT_H2_OFFSET - COINB1_LEADING_ZEROS;

/// The work root of a stratum job: the prefix above, then `coinb1` (the gateway's leading
/// zeros and H2), the extranonce, and `coinb2`, which is empty under version 2. None unless
/// the four total a whole leaf, which is what says the gateway sent the layout `work_root`
/// builds.
pub fn work_root_from_stratum(coinb1: &[u8], extranonce: &[u8], coinb2: &[u8]) -> Option<[u8; 32]> {
    let mut leaf = Vec::with_capacity(WORK_ROOT_LEAF_SIZE);
    leaf.resize(STRATUM_LEAF_PREFIX_LEN, 0);
    leaf.extend_from_slice(coinb1);
    leaf.extend_from_slice(extranonce);
    leaf.extend_from_slice(coinb2);
    let leaf: [u8; WORK_ROOT_LEAF_SIZE] = leaf.try_into().ok()?;
    Some(blake2b_256(&leaf))
}

pub fn xor_key_hash(xor_key: &XorKey) -> [u8; 32] {
    tagged_sha256("Bitcoin block hash PoW XOR key", xor_key)
}

pub fn prevblock_hidden(prev_block: &[u8; 32]) -> [u8; 32] {
    let display = crate::bitcoin::reversed(prev_block);
    let mut out = tagged_sha256("Bitcoin prevblock header, hashed", &display);
    out[..PREVBLOCK_HIDDEN_CLEARED_BYTES].fill(0);
    out
}

pub fn xor_key_mask(xor_key: &XorKey, clear_bits: u8) -> [u8; 32] {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The miner builds the work root from the stratum fields and the pool builds it from a
    /// header. Both reach `work_root`, so a change to `WORK_ROOT_H2_OFFSET` or to
    /// `COINB1_LEADING_ZEROS` moves them together rather than silently parting them.
    #[test]
    fn the_stratum_leaf_and_the_header_leaf_are_the_same_work_root() {
        let h2 = crate::fixtures::ramp(0x11);
        let extranonce: [u8; 16] = std::array::from_fn(|i| 0xa0 + i as u8);

        let mut coinb1 = vec![0u8; COINB1_LEADING_ZEROS];
        coinb1.extend_from_slice(&h2);
        assert_eq!(
            work_root_from_stratum(&coinb1, &extranonce, &[]),
            Some(work_root(&h2, &extranonce)),
            "the gateway's coinb1 plus the miner's prefix is the header's leaf"
        );
        assert_eq!(STRATUM_LEAF_PREFIX_LEN + coinb1.len(), WORK_ROOT_EXTRANONCE_OFFSET);

        let header = BlockHeaderV2 { extranonce, ..Default::default() };
        let stages = header.hash_stages();
        assert_eq!(stages.work_root, work_root(&stages.h2, &extranonce));
    }

    #[test]
    fn a_stratum_leaf_of_the_wrong_length_is_refused_rather_than_padded() {
        let h2 = crate::fixtures::ramp(0);
        let mut coinb1 = vec![0u8; COINB1_LEADING_ZEROS];
        coinb1.extend_from_slice(&h2);
        assert_eq!(work_root_from_stratum(&coinb1, &[0u8; 15], &[]), None, "short extranonce");
        assert_eq!(work_root_from_stratum(&coinb1, &[0u8; 16], &[0]), None, "coinb2 is not empty");
        assert_eq!(work_root_from_stratum(&coinb1[1..], &[0u8; 16], &[]), None, "short coinb1");
    }
}
