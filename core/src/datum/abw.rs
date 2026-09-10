use super::framing::STRUCT_END;
use crate::cursor::Cursor;
use bytes::BufMut as _;

pub const DRAFT_REVISION: u8 = 0;
pub const ASSIGNMENT_SLOTS: u8 = 16;
pub const SHARE_TARGET_BASE_BITS: u8 = 32;

pub type XorKey = crate::header::U128;
pub type SlotKeys = [Option<XorKey>; ASSIGNMENT_SLOTS as usize];

pub mod subcmd {
    pub const CANDIDATE_RECEIPT: u8 = 0xA5;
    pub const ACTIVATION: u8 = 0xA6;
    pub const CANDIDATE_RELEASE: u8 = 0xA7;
    pub const ASSIGNMENT_NOTICE: u8 = 0xA8;
    pub const REVEAL: u8 = 0xA9;
}

pub fn clear_bits(target_pot: u8) -> u8 {
    (u32::from(SHARE_TARGET_BASE_BITS) + u32::from(target_pot)).min(u32::from(u8::MAX)) as u8
}

pub use crate::header::xor_key_hash;

pub fn key_matches_hash(xor_key: &XorKey, hash: &[u8; 32]) -> bool {
    xor_key_hash(xor_key) == *hash
}

pub fn random_key() -> XorKey {
    crate::rand::bytes()
}

pub fn raw_hash_le(hash2: &[u8; 32]) -> [u8; 32] {
    crate::bitcoin::reversed(hash2)
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("truncated ABW message: {0}")]
    Truncated(&'static str),
    #[error("bad ABW revision {0}")]
    BadRevision(u8),
    #[error("ABW slot {0} out of range")]
    BadSlot(u8),
    #[error("unknown ABW flags {0:#04x}")]
    BadFlags(u8),
    #[error("missing 0xFE terminator or trailing bytes")]
    BadShape,
}

impl From<crate::cursor::Truncated> for Error {
    fn from(t: crate::cursor::Truncated) -> Self {
        Self::Truncated(t.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssignmentNotice {
    pub active: bool,
    pub slot: u8,
    pub key_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Activation {
    pub slot: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub slot: u8,
    pub raw_pow_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reveal {
    pub slot: u8,
    pub xor_key: XorKey,
}

const MAX_FRAME_LEN: usize = 2 + 1 + 32 + 1;

fn frame(subcmd: u8, body: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAX_FRAME_LEN);
    out.put_u8(subcmd);
    out.put_u8(DRAFT_REVISION);
    body(&mut out);
    out.put_u8(STRUCT_END);
    out
}

fn open(data: &[u8], subcmd: u8) -> Result<Cursor<'_>, Error> {
    let mut c = Cursor::new(data);
    c.skip_if(subcmd);
    let rev = c.u8("revision")?;
    if rev != DRAFT_REVISION {
        return Err(Error::BadRevision(rev));
    }
    Ok(c)
}

fn slot_checked(slot: u8) -> Result<u8, Error> {
    if slot >= ASSIGNMENT_SLOTS {
        return Err(Error::BadSlot(slot));
    }
    Ok(slot)
}

fn close(c: &mut Cursor<'_>) -> Result<(), Error> {
    if c.u8("terminator")? != STRUCT_END || !c.at_end() {
        return Err(Error::BadShape);
    }
    Ok(())
}

impl AssignmentNotice {
    pub fn encode(&self) -> Vec<u8> {
        frame(subcmd::ASSIGNMENT_NOTICE, |out| {
            out.put_u8(u8::from(self.active));
            out.put_u8(self.slot);
            out.put_slice(&self.key_hash);
        })
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut c = open(data, subcmd::ASSIGNMENT_NOTICE)?;
        let flags = c.u8("flags")?;
        if flags & !0x01 != 0 {
            return Err(Error::BadFlags(flags));
        }
        let slot = slot_checked(c.u8("slot")?)?;
        let key_hash: [u8; 32] = c.arr("key hash")?;
        close(&mut c)?;
        Ok(Self { active: flags & 0x01 != 0, slot, key_hash })
    }
}

impl Activation {
    pub fn encode(&self) -> Vec<u8> {
        frame(subcmd::ACTIVATION, |out| out.put_u8(self.slot))
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut c = open(data, subcmd::ACTIVATION)?;
        let slot = slot_checked(c.u8("slot")?)?;
        close(&mut c)?;
        Ok(Self { slot })
    }
}

impl Candidate {
    pub fn encode(&self, subcmd: u8) -> Vec<u8> {
        debug_assert!(matches!(subcmd, subcmd::CANDIDATE_RECEIPT | subcmd::CANDIDATE_RELEASE));
        frame(subcmd, |out| {
            out.put_u8(self.slot);
            out.put_slice(&self.raw_pow_hash);
        })
    }

    pub fn decode(data: &[u8], subcmd: u8) -> Result<Self, Error> {
        let mut c = open(data, subcmd)?;
        let slot = slot_checked(c.u8("slot")?)?;
        let raw_pow_hash: [u8; 32] = c.arr("raw pow hash")?;
        close(&mut c)?;
        Ok(Self { slot, raw_pow_hash })
    }
}

impl Reveal {
    pub fn encode(&self) -> Vec<u8> {
        frame(subcmd::REVEAL, |out| {
            out.put_u8(self.slot);
            out.put_slice(&self.xor_key);
        })
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut c = open(data, subcmd::REVEAL)?;
        let slot = slot_checked(c.u8("slot")?)?;
        let xor_key: XorKey = c.arr("xor key")?;
        close(&mut c)?;
        Ok(Self { slot, xor_key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{HeaderV2, xor_mask};

    #[test]
    fn clear_bits_matches_the_c_vectors() {
        assert_eq!(clear_bits(0), 32);
        assert_eq!(clear_bits(10), 42);
        assert_eq!(clear_bits(223), 255);
        assert_eq!(clear_bits(255), 255);
    }

    #[test]
    fn key_hash_matches_the_header_commitment_path() {
        let mut key = [0u8; 16];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8 + 1;
        }
        let h = HeaderV2 { xor_key: key, ..Default::default() };
        assert_eq!(h.precompute(), h.precompute_with_key_hash(xor_key_hash(&key)));
        assert!(key_matches_hash(&key, &xor_key_hash(&key)));
        let mut wrong = xor_key_hash(&key);
        wrong[0] ^= 1;
        assert!(!key_matches_hash(&key, &wrong));
    }

    #[test]
    fn the_mask_leaves_exactly_the_share_bits_clear() {
        let key = [0x5au8; 16];
        let m = xor_mask(&key, clear_bits(10));
        assert!(m[..5].iter().all(|&b| b == 0));
        assert_eq!(m[5] & 0xC0, 0);
        assert!(m[6..].iter().any(|&b| b != 0));
        assert_eq!(xor_mask(&[0u8; 16], 0), [0u8; 32]);
    }

    #[test]
    fn the_pool_and_a_commitment_only_gateway_compute_the_same_raw_hash() {
        let key = {
            let mut k = [0u8; 16];
            for (i, b) in k.iter_mut().enumerate() {
                *b = (i as u8) * 7 + 1;
            }
            k
        };
        let pot = 10u8;
        let cb = clear_bits(pot);

        let mut pool = HeaderV2 {
            version: 0x2000_0000,
            merkle_root: [0x33; 32],
            time: 1_700_000_000,
            bits: 0x1d00ffff,
            nonce: 0xdead_beef,
            extranonce: [0x44; 16],
            txcount: 1,
            xor_key: key,
            xor_key_mask_clear_bits: cb,
            height: 961_632,
            ..Default::default()
        };
        pool.prev_block = [0x22; 32];
        let (pool_pow, pool_block) = pool.pow_and_block_hash();

        let mut gw = pool.clone();
        gw.xor_key = [0u8; 16];
        let gw_pre = gw.precompute_with_key_hash(xor_key_hash(&key));

        let gw_asic = gw.asic_input_with(&gw_pre.hash1, &gw_pre.h2);
        let gw_raw = crate::header::blake2b_256(&gw_asic);
        assert_eq!(gw_raw, pool_pow, "raw hash must not depend on holding the key");

        let cleared_bytes = (cb / 8) as usize;
        assert_eq!(&pool_block[..cleared_bytes], &pool_pow[..cleared_bytes]);
        assert!(pool_block[cleared_bytes..] != pool_pow[cleared_bytes..]);
    }

    #[test]
    fn raw_hash_le_reverses_the_blake2b_output() {
        let hash2: [u8; 32] = std::array::from_fn(|i| i as u8);
        let le = raw_hash_le(&hash2);
        assert_eq!(le[0], 31);
        assert_eq!(le[31], 0);
        assert_eq!(raw_hash_le(&le), hash2);
    }

    #[test]
    fn messages_round_trip_at_the_c_lengths() {
        let notice = AssignmentNotice { active: true, slot: 3, key_hash: [0xab; 32] };
        let b = notice.encode();
        assert_eq!(b.len(), 37, "A8 payload is 36 bytes after the subcommand");
        assert_eq!((b[0], b[1], b[2], b[3]), (0xA8, 0, 1, 3));
        assert_eq!(b[36], STRUCT_END);
        assert_eq!(AssignmentNotice::decode(&b).unwrap(), notice);

        let act = Activation { slot: 3 };
        let b = act.encode();
        assert_eq!(b, vec![0xA6, 0, 3, 0xFE]);
        assert_eq!(Activation::decode(&b).unwrap(), act);

        let cand = Candidate { slot: 3, raw_pow_hash: [0x80; 32] };
        let b = cand.encode(subcmd::CANDIDATE_RECEIPT);
        assert_eq!(b.len(), 36);
        assert_eq!(b[0], 0xA5);
        assert_eq!(Candidate::decode(&b, subcmd::CANDIDATE_RECEIPT).unwrap(), cand);
        let b = cand.encode(subcmd::CANDIDATE_RELEASE);
        assert_eq!(b[0], 0xA7);
        assert_eq!(Candidate::decode(&b, subcmd::CANDIDATE_RELEASE).unwrap(), cand);

        let reveal = Reveal { slot: 3, xor_key: [0x11; 16] };
        let b = reveal.encode();
        assert_eq!(b.len(), 20, "A9 payload is 19 bytes after the subcommand");
        assert_eq!(Reveal::decode(&b).unwrap(), reveal);
    }

    #[test]
    fn malformed_messages_are_refused() {
        let good = AssignmentNotice { active: false, slot: 0, key_hash: [1; 32] }.encode();
        let mut bad = good.clone();
        bad[1] = 1;
        assert!(matches!(AssignmentNotice::decode(&bad), Err(Error::BadRevision(1))));
        let mut bad = good.clone();
        bad[2] = 0x02;
        assert!(matches!(AssignmentNotice::decode(&bad), Err(Error::BadFlags(2))));
        let mut bad = good.clone();
        bad[3] = 16;
        assert!(matches!(AssignmentNotice::decode(&bad), Err(Error::BadSlot(16))));
        let mut bad = good.clone();
        bad[36] = 0;
        assert!(matches!(AssignmentNotice::decode(&bad), Err(Error::BadShape)));
        let mut bad = good;
        bad.push(0x00);
        assert!(matches!(AssignmentNotice::decode(&bad), Err(Error::BadShape)));
        let mut bad = Reveal { slot: 3, xor_key: [2; 16] }.encode();
        bad[19] = 0;
        assert!(matches!(Reveal::decode(&bad), Err(Error::BadShape)));
    }
}
