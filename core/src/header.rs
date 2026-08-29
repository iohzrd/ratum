use blake2::Blake2b;
use blake2::digest::Digest as _;
use blake2::digest::consts::U32;
use sha2::Sha256;

pub const HEADER_V2_SIZE: usize = 164;
/// Set in the serialized version word to mark a version 2 header; not part of the version.
pub const V2_FLAG: u32 = 0x8000_0000;
/// Knots `BlockHeaderFlag::UseTimeOffset`.
pub const FLAG_USE_TIME_OFFSET: u8 = 4;
/// The ASIC profile, the low two bits: Knots has no named constant (`m_flags & 3` in `block.cpp`).
pub const FLAG_PROFILE_MASK: u8 = 3;

pub const ASIC_INPUT_LEN: [usize; 4] = [80, 80, 128, 160];

pub type U256 = [u8; 32];
pub type U128 = [u8; 16];

/// The version 2 header. Field names follow the gateway's `T_DATUM_HEADER_V2` (`prev_block`,
/// `time`, `bits`); elsewhere in this crate the Bitcoin header fields are `prev_hash`, `ntime`
/// and `nbits`.
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

/// BIP340-style tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data).
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
    /// What the serialized header carries: the time less `time_offset` when
    /// `FLAG_USE_TIME_OFFSET` is set. `deserialize` adds it back, so `time` is always the block
    /// time (nTime) in memory.
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
            // Profiles 0, 2 and 3 lay the fields out identically and differ in how much
            // zero padding precedes them and in what fills the 32 bytes after it: profile
            // 0 puts the hidden previous block hash there, where the Siacoin layout puts
            // the parent id; 2 and 3 put h2 there, after 48 or 80 zero bytes.
            p => {
                let zeros = match p {
                    2 => 48,
                    3 => 80,
                    _ => 0,
                };
                ss.resize(zeros, 0);
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

        // The hardware does receive the previous block hash, but only as the tagged hash
        // `prevblock_hidden` derives, so h1 commits to it as well.
        let mut prev_display = self.prev_block;
        prev_display.reverse();

        let mut h1d = Vec::with_capacity(119);
        // The node hashes the complete version, with the v2 flag bit set, into h1
        // (`block.cpp` GetHash: `h1 << GetCompleteVersion()`). `self.version` holds the
        // version with the flag stripped, so restore it here.
        h1d.extend_from_slice(&(self.version as u32 | V2_FLAG).to_le_bytes());
        h1d.extend_from_slice(&prev_display);
        h1d.extend_from_slice(&self.height.to_le_bytes());
        h1d.extend_from_slice(&self.merkle_root);
        h1d.extend_from_slice(&self.time_on_wire().to_le_bytes());
        // Reserved for an extended 40-bit time, per primitives/block.cpp.
        h1d.push(0);
        h1d.extend_from_slice(&self.bits.to_le_bytes());
        h1d.extend_from_slice(&(self.txcount as u32).to_le_bytes());
        h1d.push(self.flags);
        h1d.push(self.xor_key_mask_clear_bits);
        h1d.extend_from_slice(&xor_key_hash);
        debug_assert_eq!(h1d.len(), 119);
        let h1 = tagged_sha256("Bitcoin block header 1", &h1d);

        // Knots writes 32 zero bytes between h1 and `m_mm_rhs` (`block.cpp`:
        // `h2 << zeros << zeros`).
        let mut h2d = [0u8; 96];
        h2d[..32].copy_from_slice(&h1);
        h2d[64..].copy_from_slice(&self.mm_rhs);
        let h2 = tagged_sha256("Merge-mining hook", &h2d);

        // Stratum carries 51 of these 52 bytes: coinb1 (the last three bytes of the zero word,
        // then h2: 35 bytes) and the 16-byte extranonce. The word's first byte is the 0x00 leaf
        // prefix the Siacoin hasher adds itself, so coinb1 does not carry it.
        let mut ss = [0u8; 52];
        ss[4..36].copy_from_slice(&h2);
        ss[36..].copy_from_slice(&self.extranonce);
        let hash1 = blake2b_256(&ss);

        let mask = xor_mask(&self.xor_key, self.xor_key_mask_clear_bits);

        Precomputed { xor_key_hash, h1, h2, hash1, mask }
    }

    pub fn hash_components(&self) -> HashComponents {
        let pre = self.precompute();
        let asic_input = self.asic_input_with(&pre.hash1, &pre.h2);
        let hash2 = blake2b_256(&asic_input);
        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = hash2[i] ^ pre.mask[i];
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

    /// The hash in the byte order Knots returns it in; `HashComponents::result` is the
    /// reverse of it, which is the order targets are compared in.
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

/// The 32 bytes the hardware is given in place of the previous block hash. Profile 0
/// hashes this rather than the previous block hash itself, so it is also what
/// `mining.notify` carries in the previous-block-hash position.
///
/// The first six bytes are cleared, which is the only form block.cpp uses the value in.
/// The Siacoin layout places a block hash in that slot, and a block hash has leading zero
/// bytes; a bare tagged hash does not, so the clearing gives this value the same form.
pub fn prevblock_hidden(prev_block: &U256) -> [u8; 32] {
    let mut display = *prev_block;
    display.reverse();
    let mut out = tagged_sha256("Bitcoin prevblock header, hashed", &display);
    out[..6].fill(0);
    out
}

/// No key means no mask, matching `if (!m_xor_key.IsNull())` in block.cpp.
pub fn xor_mask(xor_key: &U128, clear_bits: u8) -> [u8; 32] {
    if xor_key.iter().all(|&b| b == 0) {
        return [0u8; 32];
    }
    let mut m = tagged_sha256("Bitcoin block hash PoW XOR mask", xor_key);
    let clear_bytes = (clear_bits / 8) as usize;
    for b in m.iter_mut().take(clear_bytes.min(32)) {
        *b = 0;
    }
    if clear_bytes < 32 {
        m[clear_bytes] &= 0xffu8 >> (clear_bits % 8);
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
