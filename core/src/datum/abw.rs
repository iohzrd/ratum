//! Anti-block-withholding (version 3 protocol). The pool chooses a 16-byte XOR key per
//! assignment and discloses only its commitment; the mask derived from the key masks every
//! PoW hash below the top `32 + PoT` bits, so neither hasher nor gateway can distinguish a
//! block from an ordinary share until the pool reveals the key. The five subcommands here carry
//! the assignment lifecycle; the key and mask arithmetic itself lives in
//! [`crate::header`] (`xor_mask`, the `xor_key_hash` tag), because it is also consensus.

use super::framing::STRUCT_END;
use crate::cursor::Cursor;
use crate::header::tagged_sha256;

/// `DATUM_ABW_DRAFT_REVISION`: every payload's first byte after the subcommand.
pub const DRAFT_REVISION: u8 = 0;
/// `DATUM_ABW_ASSIGNMENT_SLOTS`: slots are 0..15 in the serialized message; the C gateway stores slot+1
/// internally so 0 can mean unset.
pub const ASSIGNMENT_SLOTS: u8 = 16;
/// `DATUM_ABW_SHARE_TARGET_BASE_BITS`: the clear-bits floor, matching the 32 zero bits a
/// difficulty-1 share requires.
pub const SHARE_TARGET_BASE_BITS: u8 = 32;

pub mod subcmd {
    /// Pool handled this candidate (slot + raw hash).
    pub const CANDIDATE_RECEIPT: u8 = 0xA5;
    /// Make a seeded slot the active assignment.
    pub const ACTIVATION: u8 = 0xA6;
    /// The gateway may discard this candidate (does nothing under the default gateway
    /// config, which retains every proof until the reveal).
    pub const CANDIDATE_RELEASE: u8 = 0xA7;
    /// Install a key-hash commitment into a slot, optionally activating it.
    pub const ASSIGNMENT_NOTICE: u8 = 0xA8;
    /// Disclose a slot's XOR key.
    pub const REVEAL: u8 = 0xA9;
}

/// `datum_blake2b_abw_clear_bits`: how many leading mask bits an assignment clears for a
/// share of PoT exponent `target_pot`. Exactly the bits the share check inspects, so share
/// validity is verifiable without the key and block validity is not.
pub fn clear_bits(target_pot: u8) -> u8 {
    (u32::from(SHARE_TARGET_BASE_BITS) + u32::from(target_pot)).min(255) as u8
}

/// The commitment to an XOR key that H1 carries and the assignment notice delivers.
pub fn xor_key_hash(xor_key: &[u8; 16]) -> [u8; 32] {
    tagged_sha256("Bitcoin block hash PoW XOR key", xor_key)
}

pub fn key_matches_hash(xor_key: &[u8; 16], hash: &[u8; 32]) -> bool {
    // Not secret data on this side: the commitment is public once sent.
    xor_key_hash(xor_key) == *hash
}

/// A random 16-byte XOR key from the CSPRNG, for the pool to seed an assignment with.
pub fn random_key() -> [u8; 16] {
    let mut key = [0u8; 16];
    dryoc::rng::copy_randombytes(&mut key);
    key
}

/// The raw PoW hash in the byte order the C gateway retains a proof under and matches an
/// 0xA5 receipt and the 0x8F exact reference against: `datum_blake2b_pow_hash_le`, the
/// BLAKE2b output reversed. `HashComponents::hash2` is the BLAKE2b output order.
pub fn raw_hash_le(hash2: &[u8; 32]) -> [u8; 32] {
    let mut le = *hash2;
    le.reverse();
    le
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
        Error::Truncated(t.0)
    }
}

/// 0xA8: `A8 00 <flags> <slot> <key_hash 32> FE`. `active` is flag bit 0; the C gateway
/// rejects any other flag bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssignmentNotice {
    pub active: bool,
    pub slot: u8,
    pub key_hash: [u8; 32],
}

/// 0xA6: `A6 00 <slot> FE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Activation {
    pub slot: u8,
}

/// 0xA5 and 0xA7 share one layout: `Ax 00 <slot> <raw_pow_hash 32> FE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub slot: u8,
    pub raw_pow_hash: [u8; 32],
}

/// 0xA9: `A9 00 <slot> <xor_key 16> FE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reveal {
    pub slot: u8,
    pub xor_key: [u8; 16],
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

/// The C handlers check exact lengths, so decoding requires the terminator to be the last
/// byte.
fn close(c: &mut Cursor<'_>) -> Result<(), Error> {
    if c.u8("terminator")? != STRUCT_END || !c.at_end() {
        return Err(Error::BadShape);
    }
    Ok(())
}

impl AssignmentNotice {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(37);
        out.push(subcmd::ASSIGNMENT_NOTICE);
        out.push(DRAFT_REVISION);
        out.push(self.active as u8);
        out.push(self.slot);
        out.extend_from_slice(&self.key_hash);
        out.push(STRUCT_END);
        out
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
        Ok(AssignmentNotice { active: flags & 0x01 != 0, slot, key_hash })
    }
}

impl Activation {
    pub fn encode(&self) -> Vec<u8> {
        vec![subcmd::ACTIVATION, DRAFT_REVISION, self.slot, STRUCT_END]
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut c = open(data, subcmd::ACTIVATION)?;
        let slot = slot_checked(c.u8("slot")?)?;
        close(&mut c)?;
        Ok(Activation { slot })
    }
}

impl Candidate {
    pub fn encode(&self, subcmd: u8) -> Vec<u8> {
        debug_assert!(matches!(subcmd, subcmd::CANDIDATE_RECEIPT | subcmd::CANDIDATE_RELEASE));
        let mut out = Vec::with_capacity(36);
        out.push(subcmd);
        out.push(DRAFT_REVISION);
        out.push(self.slot);
        out.extend_from_slice(&self.raw_pow_hash);
        out.push(STRUCT_END);
        out
    }

    pub fn decode(data: &[u8], subcmd: u8) -> Result<Self, Error> {
        let mut c = open(data, subcmd)?;
        let slot = slot_checked(c.u8("slot")?)?;
        let raw_pow_hash: [u8; 32] = c.arr("raw pow hash")?;
        close(&mut c)?;
        Ok(Candidate { slot, raw_pow_hash })
    }
}

impl Reveal {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(20);
        out.push(subcmd::REVEAL);
        out.push(DRAFT_REVISION);
        out.push(self.slot);
        out.extend_from_slice(&self.xor_key);
        out.push(STRUCT_END);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut c = open(data, subcmd::REVEAL)?;
        let slot = slot_checked(c.u8("slot")?)?;
        let xor_key: [u8; 16] = c.arr("xor key")?;
        close(&mut c)?;
        Ok(Reveal { slot, xor_key })
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
        // The C test proves header_commitment(key) == header_commitment_from_key_hash(hash);
        // here the same key hash must be what a HeaderV2 carrying the key commits to.
        let mut key = [0u8; 16];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8 + 1;
        }
        let h = HeaderV2 { xor_key: key, ..Default::default() };
        assert_eq!(h.precompute().xor_key_hash, xor_key_hash(&key));
        assert!(key_matches_hash(&key, &xor_key_hash(&key)));
        let mut wrong = xor_key_hash(&key);
        wrong[0] ^= 1;
        assert!(!key_matches_hash(&key, &wrong));
    }

    #[test]
    fn the_mask_leaves_exactly_the_share_bits_clear() {
        let key = [0x5au8; 16];
        let m = xor_mask(&key, clear_bits(10));
        // 42 bits: five whole bytes and two bits of the sixth.
        assert!(m[..5].iter().all(|&b| b == 0));
        assert_eq!(m[5] & 0xC0, 0);
        assert!(m[6..].iter().any(|&b| b != 0));
        // The all-zero key means no mask, matching the pre-ABW behavior.
        assert_eq!(xor_mask(&[0u8; 16], 0), [0u8; 32]);
    }

    #[test]
    fn the_pool_and_a_commitment_only_gateway_compute_the_same_raw_hash() {
        // The pool holds the key; the gateway holds only its commitment. Both must arrive at
        // the same unmasked hash (H2 depends on the key hash through H1), and the masked
        // result must equal the raw hash on the top 32+PoT bits the share check reads.
        let key = {
            let mut k = [0u8; 16];
            for (i, b) in k.iter_mut().enumerate() {
                *b = (i as u8) * 7 + 1;
            }
            k
        };
        let pot = 10u8;
        let cb = clear_bits(pot);

        // The pool's header carries the real key and clear bits.
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
        let pool_hc = pool.hash_components();

        // The gateway builds the same header but with no key, committing to the hash instead.
        let mut gw = pool.clone();
        gw.xor_key = [0u8; 16];
        let gw_pre = gw.precompute_with_key_hash(xor_key_hash(&key));

        // The gateway's ASIC input and hash2 (the raw hash) match the pool's, without the key.
        let gw_asic = gw.asic_input_with(&gw_pre.hash1, &gw_pre.h2);
        let gw_raw = crate::header::blake2b_256(&gw_asic);
        assert_eq!(gw_raw, pool_hc.hash2, "raw hash must not depend on holding the key");

        // The masked result (what consensus compares) equals the raw hash on the top
        // 42 bits, the ones the share check at PoT 10 inspects.
        let cleared_bytes = (cb / 8) as usize;
        assert_eq!(&pool_hc.result[..cleared_bytes], &pool_hc.hash2[..cleared_bytes]);
        // Below the cleared prefix the mask is nonzero, so a block is indistinguishable from a
        // share without the key.
        assert!(pool_hc.result[cleared_bytes..] != pool_hc.hash2[cleared_bytes..]);
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
        // The C reveal test overwrites the terminator with 0.
        let mut bad = Reveal { slot: 3, xor_key: [2; 16] }.encode();
        bad[19] = 0;
        assert!(matches!(Reveal::decode(&bad), Err(Error::BadShape)));
    }
}
