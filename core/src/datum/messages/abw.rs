//! The anti-block-withholding messages. The pool assigns a slot and commits to its XOR key by the
//! key's hash; a gateway mining under the commitment cannot tell a block from a share. The pool
//! acknowledges each candidate by its raw BLAKE2b hash and discloses the key once the slot is
//! retired, which is what lets the gateway check afterwards that every block it found was
//! acknowledged.

use super::{Error, STRUCT_END, open_message, read_final_terminator};
use crate::header::XorKey;
use crate::reader::ByteReader;
use bytes::BufMut as _;

pub(crate) const DRAFT_REVISION: u8 = 0;
pub const ASSIGNMENT_SLOTS: u8 = 16;
pub(crate) const SHARE_TARGET_BASE_BITS: u8 = 32;
pub(crate) const ASSIGNMENT_ACTIVE: u8 = 0x01;

pub mod subcmd {
    pub const CANDIDATE_RECEIPT: u8 = 0xA5;
    /// Reserved: the draft's separate activation message. The pool activates a slot with
    /// an `AssignmentNotice` carrying `active`, so nothing sends this and the gateway has no
    /// handler for it.
    pub const RESERVED_ACTIVATION: u8 = 0xA6;
    pub const CANDIDATE_RELEASE: u8 = 0xA7;
    pub const ASSIGNMENT_NOTICE: u8 = 0xA8;
    pub const REVEAL: u8 = 0xA9;
}

pub(crate) fn clear_bits(target_byte: u8) -> u8 {
    (u32::from(SHARE_TARGET_BASE_BITS) + u32::from(target_byte)).min(u32::from(u8::MAX)) as u8
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssignmentNotice {
    pub active: bool,
    pub slot: u8,
    pub key_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateRef {
    pub slot: u8,
    pub raw_pow_hash_le: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reveal {
    pub slot: u8,
    pub xor_key: XorKey,
}

const MAX_MESSAGE_LEN: usize = 2 + 1 + 32 + 1;

fn message(subcmd: u8, body: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAX_MESSAGE_LEN);
    out.put_u8(subcmd);
    out.put_u8(DRAFT_REVISION);
    body(&mut out);
    out.put_u8(STRUCT_END);
    out
}

fn open(data: &[u8], subcmd: u8) -> Result<ByteReader<'_>, Error> {
    let mut c = open_message(data, subcmd)?;
    let rev = c.u8("revision")?;
    if rev != DRAFT_REVISION {
        return Err(Error::BadVersion(rev));
    }
    Ok(c)
}

fn slot_checked(slot: u8) -> Result<u8, Error> {
    if slot >= ASSIGNMENT_SLOTS {
        return Err(Error::BadSlot(slot));
    }
    Ok(slot)
}

impl AssignmentNotice {
    pub fn encode(&self) -> Vec<u8> {
        message(subcmd::ASSIGNMENT_NOTICE, |out| {
            out.put_u8(if self.active { ASSIGNMENT_ACTIVE } else { 0 });
            out.put_u8(self.slot);
            out.put_slice(&self.key_hash);
        })
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut c = open(data, subcmd::ASSIGNMENT_NOTICE)?;
        let flags = c.u8("flags")?;
        if flags & !ASSIGNMENT_ACTIVE != 0 {
            return Err(Error::BadFlags(flags));
        }
        let slot = slot_checked(c.u8("slot")?)?;
        let key_hash: [u8; 32] = c.arr("key hash")?;
        read_final_terminator(&mut c)?;
        Ok(Self { active: flags & ASSIGNMENT_ACTIVE != 0, slot, key_hash })
    }
}

impl CandidateRef {
    /// The reference to the share whose BLAKE2b output is `raw_pow_hash`: the output reversed.
    pub fn new(slot: u8, raw_pow_hash: &[u8; 32]) -> Self {
        Self { slot, raw_pow_hash_le: crate::bitcoin::reversed(raw_pow_hash) }
    }

    pub fn encode_candidate(&self, subcmd: u8) -> Vec<u8> {
        debug_assert!(matches!(subcmd, subcmd::CANDIDATE_RECEIPT | subcmd::CANDIDATE_RELEASE));
        message(subcmd, |out| {
            out.put_u8(self.slot);
            out.put_slice(&self.raw_pow_hash_le);
        })
    }

    pub fn decode_candidate(data: &[u8], subcmd: u8) -> Result<Self, Error> {
        let mut c = open(data, subcmd)?;
        let slot = slot_checked(c.u8("slot")?)?;
        let raw_pow_hash_le: [u8; 32] = c.arr("raw pow hash")?;
        read_final_terminator(&mut c)?;
        Ok(Self { slot, raw_pow_hash_le })
    }
}

impl Reveal {
    pub fn encode(&self) -> Vec<u8> {
        message(subcmd::REVEAL, |out| {
            out.put_u8(self.slot);
            out.put_slice(&self.xor_key);
        })
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut c = open(data, subcmd::REVEAL)?;
        let slot = slot_checked(c.u8("slot")?)?;
        let xor_key: XorKey = c.arr("xor key")?;
        read_final_terminator(&mut c)?;
        Ok(Self { slot, xor_key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{BlockHeaderV2, PowHashes, xor_key_hash, xor_key_mask};

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
        let h = BlockHeaderV2 { xor_key: key, ..Default::default() };
        assert_eq!(h.hash_stages(), h.hash_stages_with_key_hash(xor_key_hash(&key)));
    }

    #[test]
    fn the_mask_leaves_exactly_the_share_bits_clear() {
        let key = [0x5au8; 16];
        let m = xor_key_mask(&key, clear_bits(10));
        assert!(m[..5].iter().all(|&b| b == 0));
        assert_eq!(m[5] & 0xC0, 0);
        assert!(m[6..].iter().any(|&b| b != 0));
        assert_eq!(xor_key_mask(&[0u8; 16], 0), [0u8; 32]);
    }

    #[test]
    fn the_pool_and_a_commitment_only_gateway_compute_the_same_raw_pow_hash() {
        let key = {
            let mut k = [0u8; 16];
            for (i, b) in k.iter_mut().enumerate() {
                *b = (i as u8) * 7 + 1;
            }
            k
        };
        let target_byte = 10u8;
        let cb = clear_bits(target_byte);

        let mut pool = BlockHeaderV2 {
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
        let PowHashes { raw_pow_hash: pool_pow, block_hash: pool_block } = pool.pow_hashes();

        let mut gw = pool.clone();
        gw.xor_key = [0u8; 16];
        let gw_raw = gw.raw_pow_hash(&gw.hash_stages_with_key_hash(xor_key_hash(&key)));
        assert_eq!(gw_raw, pool_pow, "raw hash must not depend on holding the key");

        let cleared_bytes = (cb / 8) as usize;
        assert_eq!(&pool_block[..cleared_bytes], &pool_pow[..cleared_bytes]);
        assert!(pool_block[cleared_bytes..] != pool_pow[cleared_bytes..]);
    }

    #[test]
    fn a_candidate_ref_reverses_the_blake2b_output() {
        let raw_pow_hash: [u8; 32] = std::array::from_fn(|i| i as u8);
        let c = CandidateRef::new(3, &raw_pow_hash);
        assert_eq!(c.slot, 3);
        assert_eq!(c.raw_pow_hash_le[0], 31);
        assert_eq!(c.raw_pow_hash_le[31], 0);
    }

    #[test]
    fn messages_round_trip_at_the_c_lengths() {
        let notice = AssignmentNotice { active: true, slot: 3, key_hash: [0xab; 32] };
        let b = notice.encode();
        assert_eq!(b.len(), 37, "A8 payload is 36 bytes after the subcommand");
        assert_eq!((b[0], b[1], b[2], b[3]), (0xA8, 0, 1, 3));
        assert_eq!(b[36], STRUCT_END);
        assert_eq!(AssignmentNotice::decode(&b).unwrap(), notice);

        let cand = CandidateRef { slot: 3, raw_pow_hash_le: [0x80; 32] };
        let b = cand.encode_candidate(subcmd::CANDIDATE_RECEIPT);
        assert_eq!(b.len(), 36);
        assert_eq!(b[0], 0xA5);
        assert_eq!(CandidateRef::decode_candidate(&b, subcmd::CANDIDATE_RECEIPT).unwrap(), cand);
        let b = cand.encode_candidate(subcmd::CANDIDATE_RELEASE);
        assert_eq!(b[0], 0xA7);
        assert_eq!(CandidateRef::decode_candidate(&b, subcmd::CANDIDATE_RELEASE).unwrap(), cand);

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
        assert!(matches!(AssignmentNotice::decode(&bad), Err(Error::BadVersion(1))));
        let mut bad = good.clone();
        bad[2] = 0x02;
        assert!(matches!(AssignmentNotice::decode(&bad), Err(Error::BadFlags(2))));
        let mut bad = good.clone();
        bad[3] = 16;
        assert!(matches!(AssignmentNotice::decode(&bad), Err(Error::BadSlot(16))));
        let mut bad = good.clone();
        bad[36] = 0;
        assert!(matches!(AssignmentNotice::decode(&bad), Err(Error::BadTerminator)));
        let mut bad = good;
        bad.push(0x00);
        assert!(matches!(AssignmentNotice::decode(&bad), Err(Error::Malformed(_))));
        let mut bad = Reveal { slot: 3, xor_key: [2; 16] }.encode();
        bad[19] = 0;
        assert!(matches!(Reveal::decode(&bad), Err(Error::BadTerminator)));
    }
}
