use super::framing::STRUCT_END;
use crate::cursor::Cursor;
use crate::header::tagged_sha256;

pub const DRAFT_REVISION: u8 = 0;
pub const ASSIGNMENT_SLOTS: u8 = 16;
pub const SHARE_TARGET_BASE_BITS: u8 = 32;

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

pub fn xor_key_hash(xor_key: &[u8; 16]) -> [u8; 32] {
    tagged_sha256("Bitcoin block hash PoW XOR key", xor_key)
}

pub fn key_matches_hash(xor_key: &[u8; 16], hash: &[u8; 32]) -> bool {
    xor_key_hash(xor_key) == *hash
}

pub fn random_key() -> [u8; 16] {
    crate::rand::bytes()
}

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
