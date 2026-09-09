use crate::cursor::{Cursor, Truncated};
use crate::header::HeaderV2;

pub use super::messages::client_subcmd::SUBMIT_POW;
pub const SECTION_JOB: u8 = 0x01;
pub const SECTION_COINBASE: u8 = 0x02;
pub const SECTION_BLAKE2B: u8 = 0x03;
pub const SECTION_ABW_SLOT: u8 = 0x05;
pub const BLAKE2B_ALGORITHM: u8 = 0x01;
pub const BLAKE2B_TIME: u8 = 0x04;
pub const FLAG_IS_BLOCK: u8 = 0x01;
pub const FLAG_SUBSIDY_ONLY: u8 = 0x02;
pub const FLAG_QUICKDIFF: u8 = 0x04;
pub const FLAG_BLAKE2B: u8 = 0x08;
pub const RESERVED_USE_TIME_OFFSET: u8 = 0x01;
pub use super::framing::STRUCT_END;
pub const EXTRANONCE_SIZE: usize = 12;
pub const EXTRANONCE_SIZE_V2: usize = 16;
pub const EXTRANONCE_V2_PAD: usize = EXTRANONCE_SIZE_V2 - EXTRANONCE_SIZE;
pub const EXTRANONCE1_SIZE: usize = EXTRANONCE_V2_PAD + size_of::<u32>();
pub const EXTRANONCE2_SIZE: usize = EXTRANONCE_SIZE_V2 - EXTRANONCE1_SIZE;
pub const SIA_FIELD_SIZE: usize = 2 * size_of::<u32>();
pub const SIA_FIELD_HALF: usize = size_of::<u32>();
pub const RESERVED_SIZE: usize = 4;
pub const COINBASE_ID_SUBSIDY_ONLY: u8 = 0xFF;
pub const MAX_JOBS: usize = 256;
pub const MAX_COINBASE_SECTION_BYTES: usize = crate::datum::messages::MAX_COINBASER_BLOB + 1024;
pub const MAX_MERKLE_BRANCHES: usize = 24;
pub const MAX_USERNAME: usize = 384;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("truncated share: {0}")]
    Truncated(&'static str),
    #[error("extranonce size {0}, expected 12")]
    BadExtranonceSize(u8),
    #[error("username not terminated")]
    BadUsername,
    #[error("merkle branch count {0} too large")]
    BadMerkleCount(u8),
    #[error("unknown section marker {0:#04x}")]
    UnknownSection(u8),
    #[error("malformed BLAKE2b section")]
    BadBlake2bSection,
    #[error("no BLAKE2b section")]
    MissingBlake2bSection,
}

impl From<Truncated> for Error {
    fn from(t: Truncated) -> Self {
        Self::Truncated(t.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobSection {
    pub prev_hash: [u8; 32],
    pub target_byte_index: u16,
    pub nbits: [u8; 4],
    pub coinbaser_id: u8,
    pub height: u32,
    pub coinbase_value: u64,
    pub txn_count: u32,
    pub txn_total_weight: u32,
    pub txn_total_size: u32,
    pub txn_total_sigops: u32,
    pub merkle_branches: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinbaseSection {
    pub coinbase_id: u8,
    pub coinb1: Vec<u8>,
    pub coinb2: Vec<u8>,
}

impl CoinbaseSection {
    pub fn assemble(&self, extranonce: &[u8]) -> Vec<u8> {
        let mut tx = Vec::with_capacity(self.coinb1.len() + extranonce.len() + self.coinb2.len());
        tx.extend_from_slice(&self.coinb1);
        tx.extend_from_slice(extranonce);
        tx.extend_from_slice(&self.coinb2);
        tx
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Blake2bSection {
    pub sia_ntime: [u8; SIA_FIELD_SIZE],
    pub sia_nonce: [u8; SIA_FIELD_SIZE],
    pub time_on_wire: u32,
}

pub fn header_extranonce(extranonce: &[u8]) -> Option<[u8; EXTRANONCE_SIZE_V2]> {
    if extranonce.len() != EXTRANONCE_SIZE {
        return None;
    }
    let mut out = [0u8; EXTRANONCE_SIZE_V2];
    out[EXTRANONCE_V2_PAD..].copy_from_slice(extranonce);
    Some(out)
}

pub fn share_extranonce(field: &[u8; EXTRANONCE_SIZE_V2]) -> Option<Vec<u8>> {
    if field[..EXTRANONCE_V2_PAD] != [0u8; EXTRANONCE_V2_PAD] {
        return None;
    }
    Some(field[EXTRANONCE_V2_PAD..].to_vec())
}

/// A Sia stratum field is two little-endian u32 halves: `nonce` carries the header's
/// nonce then nonce2, `ntime` carries its time offset then nonce3.
pub fn sia_field(low: u32, high: u32) -> [u8; SIA_FIELD_SIZE] {
    let mut f = [0u8; SIA_FIELD_SIZE];
    f[..SIA_FIELD_HALF].copy_from_slice(&low.to_le_bytes());
    f[SIA_FIELD_HALF..].copy_from_slice(&high.to_le_bytes());
    f
}

pub fn sia_halves(field: &[u8; SIA_FIELD_SIZE]) -> (u32, u32) {
    let (low, high) = field.split_at(SIA_FIELD_HALF);
    let le32 = |b: &[u8]| u32::from_le_bytes(b.try_into().expect("four bytes"));
    (le32(low), le32(high))
}

impl Blake2bSection {
    pub fn from_header(h: &HeaderV2) -> Self {
        Self {
            sia_ntime: sia_field(h.time_offset, h.nonce3),
            sia_nonce: sia_field(h.nonce, h.nonce2),
            time_on_wire: h.time_on_wire(),
        }
    }

    pub fn nonce_fields(&self) -> (u32, u32) {
        sia_halves(&self.sia_nonce)
    }

    pub fn time_fields(&self) -> (u32, u32) {
        sia_halves(&self.sia_ntime)
    }
}

fn decode_job_section(r: &mut Cursor<'_>) -> Result<JobSection, Error> {
    let prev_hash: [u8; 32] = r.arr("prev hash")?;
    let target_byte_index = r.u16("target byte index")?;
    let nbits: [u8; 4] = r.arr("nbits")?;
    let coinbaser_id = r.u8("coinbaser id")?;
    let height = r.u32("height")?;
    let coinbase_value = r.u64("coinbase value")?;
    let txn_count = r.u32("txn count")?;
    let txn_total_weight = r.u32("txn weight")?;
    let txn_total_size = r.u32("txn size")?;
    let txn_total_sigops = r.u32("txn sigops")?;
    let n = r.u8("merkle count")?;
    if n as usize > MAX_MERKLE_BRANCHES {
        return Err(Error::BadMerkleCount(n));
    }
    let mut merkle_branches = Vec::with_capacity(n as usize);
    for _ in 0..n {
        merkle_branches.push(r.arr("merkle branch")?);
    }
    Ok(JobSection {
        prev_hash,
        target_byte_index,
        nbits,
        coinbaser_id,
        height,
        coinbase_value,
        txn_count,
        txn_total_weight,
        txn_total_size,
        txn_total_sigops,
        merkle_branches,
    })
}

fn encode_job_section(out: &mut Vec<u8>, j: &JobSection) {
    out.push(SECTION_JOB);
    out.extend_from_slice(&j.prev_hash);
    out.extend_from_slice(&j.target_byte_index.to_le_bytes());
    out.extend_from_slice(&j.nbits);
    out.push(j.coinbaser_id);
    out.extend_from_slice(&j.height.to_le_bytes());
    out.extend_from_slice(&j.coinbase_value.to_le_bytes());
    out.extend_from_slice(&j.txn_count.to_le_bytes());
    out.extend_from_slice(&j.txn_total_weight.to_le_bytes());
    out.extend_from_slice(&j.txn_total_size.to_le_bytes());
    out.extend_from_slice(&j.txn_total_sigops.to_le_bytes());
    out.push(j.merkle_branches.len() as u8);
    for b in &j.merkle_branches {
        out.extend_from_slice(b);
    }
}

fn decode_coinbase_section(r: &mut Cursor<'_>) -> Result<CoinbaseSection, Error> {
    let coinbase_id = r.u8("coinbase section id")?;
    let len1 = r.u16("coinb1 len")? as usize;
    let len2 = r.u16("coinb2 len")? as usize;
    let coinb1 = r.take(len1, "coinb1")?.to_vec();
    let coinb2 = r.take(len2, "coinb2")?.to_vec();
    Ok(CoinbaseSection { coinbase_id, coinb1, coinb2 })
}

fn encode_coinbase_section(out: &mut Vec<u8>, c: &CoinbaseSection) {
    out.push(SECTION_COINBASE);
    out.push(c.coinbase_id);
    out.extend_from_slice(&(c.coinb1.len() as u16).to_le_bytes());
    out.extend_from_slice(&(c.coinb2.len() as u16).to_le_bytes());
    out.extend_from_slice(&c.coinb1);
    out.extend_from_slice(&c.coinb2);
}

fn decode_blake2b_section(r: &mut Cursor<'_>) -> Result<Blake2bSection, Error> {
    if r.u8("algorithm")? != BLAKE2B_ALGORITHM {
        return Err(Error::BadBlake2bSection);
    }
    let sia_ntime: [u8; SIA_FIELD_SIZE] = r.arr("sia ntime")?;
    let sia_nonce: [u8; SIA_FIELD_SIZE] = r.arr("sia nonce")?;
    if r.u8("time marker")? != BLAKE2B_TIME {
        return Err(Error::BadBlake2bSection);
    }
    let time_on_wire = r.u32("time on wire")?;
    Ok(Blake2bSection { sia_ntime, sia_nonce, time_on_wire })
}

fn encode_blake2b_section(out: &mut Vec<u8>, b: &Blake2bSection) {
    out.push(SECTION_BLAKE2B);
    out.push(BLAKE2B_ALGORITHM);
    out.extend_from_slice(&b.sia_ntime);
    out.extend_from_slice(&b.sia_nonce);
    out.push(BLAKE2B_TIME);
    out.extend_from_slice(&b.time_on_wire.to_le_bytes());
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PowSubmit {
    pub job_id: u8,
    pub coinbase_id: u8,
    pub is_block: bool,
    pub subsidy_only: bool,
    pub quickdiff: bool,
    pub target_byte: u8,
    pub ntime: u32,
    pub nonce: u32,
    pub version: u32,
    pub extranonce: Vec<u8>,
    pub username: String,
    pub use_time_offset: bool,
    pub job: Option<JobSection>,
    pub coinbase: Option<CoinbaseSection>,
    pub blake2b: Blake2bSection,
    pub abw_slot: Option<u8>,
}

impl PowSubmit {
    pub fn target_byte_index_of(&self, job: &JobSection) -> u16 {
        self.job.as_ref().map_or(job.target_byte_index, |j| j.target_byte_index)
    }

    pub fn difficulty(&self) -> u64 {
        crate::target::diff_for_pot(self.target_byte)
    }

    pub fn prefix(data: &[u8]) -> Option<(u8, u8, u32)> {
        let mut r = Cursor::new(data);
        r.skip_if(SUBMIT_POW);
        let job_id = r.u8("job id").ok()?;
        r.u8("coinbase id").ok()?;
        r.u8("flags").ok()?;
        let target_byte = r.u8("target byte").ok()?;
        r.u32("ntime").ok()?;
        let nonce = r.u32("nonce").ok()?;
        Some((job_id, target_byte, nonce))
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut r = Cursor::new(data);
        r.skip_if(SUBMIT_POW);
        let job_id = r.u8("job id")?;
        let coinbase_id = r.u8("coinbase id")?;
        let flags = r.u8("flags")?;
        let target_byte = r.u8("target byte")?;
        let ntime = r.u32("ntime")?;
        let nonce = r.u32("nonce")?;
        let version = r.u32("version")?;
        let en_size = r.u8("extranonce size")?;
        if en_size as usize != EXTRANONCE_SIZE {
            return Err(Error::BadExtranonceSize(en_size));
        }
        let extranonce = r.take(en_size as usize, "extranonce")?.to_vec();

        let rest = r.rest();
        let nul =
            rest.iter().take(MAX_USERNAME + 1).position(|&b| b == 0).ok_or(Error::BadUsername)?;
        let username = String::from_utf8_lossy(&rest[..nul]).into_owned();
        r.advance(nul + 1, "username")?;
        let reserved = r.take(RESERVED_SIZE, "reserved")?;
        let use_time_offset = reserved[0] & RESERVED_USE_TIME_OFFSET != 0;

        let mut job = None;
        let mut coinbase = None;
        let mut blake2b = None;
        let mut abw_slot = None;
        loop {
            match r.u8("section marker")? {
                STRUCT_END => break,
                SECTION_JOB => job = Some(decode_job_section(&mut r)?),
                SECTION_COINBASE => coinbase = Some(decode_coinbase_section(&mut r)?),
                SECTION_ABW_SLOT => abw_slot = Some(r.u8("abw slot")?),
                SECTION_BLAKE2B => blake2b = Some(decode_blake2b_section(&mut r)?),
                other => return Err(Error::UnknownSection(other)),
            }
        }
        let blake2b = blake2b.ok_or(Error::MissingBlake2bSection)?;

        Ok(Self {
            job_id,
            coinbase_id,
            is_block: flags & FLAG_IS_BLOCK != 0,
            subsidy_only: flags & FLAG_SUBSIDY_ONLY != 0,
            quickdiff: flags & FLAG_QUICKDIFF != 0,
            target_byte,
            ntime,
            nonce,
            version,
            extranonce,
            username,
            use_time_offset,
            job,
            coinbase,
            blake2b,
            abw_slot,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.push(SUBMIT_POW);
        out.push(self.job_id);
        out.push(self.coinbase_id);
        let flag = |set: bool, bit: u8| if set { bit } else { 0 };
        out.push(
            flag(self.is_block, FLAG_IS_BLOCK)
                | flag(self.subsidy_only, FLAG_SUBSIDY_ONLY)
                | flag(self.quickdiff, FLAG_QUICKDIFF)
                | FLAG_BLAKE2B,
        );
        out.push(self.target_byte);
        out.extend_from_slice(&self.ntime.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.extend_from_slice(&self.version.to_le_bytes());
        out.push(self.extranonce.len() as u8);
        out.extend_from_slice(&self.extranonce);
        out.extend_from_slice(self.username.as_bytes());
        out.push(0);
        let mut reserved = [0u8; RESERVED_SIZE];
        if self.use_time_offset {
            reserved[0] |= RESERVED_USE_TIME_OFFSET;
        }
        out.extend_from_slice(&reserved);
        if let Some(j) = &self.job {
            encode_job_section(&mut out, j);
        }
        if let Some(c) = &self.coinbase {
            encode_coinbase_section(&mut out, c);
        }
        encode_blake2b_section(&mut out, &self.blake2b);
        if let Some(slot) = self.abw_slot {
            out.push(SECTION_ABW_SLOT);
            out.push(slot);
        }
        out.push(STRUCT_END);
        out
    }
}
