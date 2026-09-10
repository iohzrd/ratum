use crate::cursor::{Cursor, Truncated};
use crate::header::HeaderV2;
use bytes::BufMut as _;

use super::messages::client_subcmd::SUBMIT_POW;
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
use super::framing::STRUCT_END;
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
        tx.put_slice(&self.coinb1);
        tx.put_slice(extranonce);
        tx.put_slice(&self.coinb2);
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

pub fn sia_field(low: u32, high: u32) -> [u8; SIA_FIELD_SIZE] {
    let mut f = [0u8; SIA_FIELD_SIZE];
    let mut w = &mut f[..];
    w.put_u32_le(low);
    w.put_u32_le(high);
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
    out.put_u8(SECTION_JOB);
    out.put_slice(&j.prev_hash);
    out.put_u16_le(j.target_byte_index);
    out.put_slice(&j.nbits);
    out.put_u8(j.coinbaser_id);
    out.put_u32_le(j.height);
    out.put_u64_le(j.coinbase_value);
    out.put_u32_le(j.txn_count);
    out.put_u32_le(j.txn_total_weight);
    out.put_u32_le(j.txn_total_size);
    out.put_u32_le(j.txn_total_sigops);
    out.put_u8(j.merkle_branches.len() as u8);
    for b in &j.merkle_branches {
        out.put_slice(b);
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
    out.put_u8(SECTION_COINBASE);
    out.put_u8(c.coinbase_id);
    out.put_u16_le(c.coinb1.len() as u16);
    out.put_u16_le(c.coinb2.len() as u16);
    out.put_slice(&c.coinb1);
    out.put_slice(&c.coinb2);
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
    out.put_u8(SECTION_BLAKE2B);
    out.put_u8(BLAKE2B_ALGORITHM);
    out.put_slice(&b.sia_ntime);
    out.put_slice(&b.sia_nonce);
    out.put_u8(BLAKE2B_TIME);
    out.put_u32_le(b.time_on_wire);
}

struct Prefix {
    job_id: u8,
    coinbase_id: u8,
    flags: u8,
    target_byte: u8,
    ntime: u32,
    nonce: u32,
}

impl Prefix {
    fn read(r: &mut Cursor<'_>) -> Result<Self, Truncated> {
        r.skip_if(SUBMIT_POW);
        Ok(Self {
            job_id: r.u8("job id")?,
            coinbase_id: r.u8("coinbase id")?,
            flags: r.u8("flags")?,
            target_byte: r.u8("target byte")?,
            ntime: r.u32("ntime")?,
            nonce: r.u32("nonce")?,
        })
    }
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
        let p = Prefix::read(&mut Cursor::new(data)).ok()?;
        Some((p.job_id, p.target_byte, p.nonce))
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut r = Cursor::new(data);
        let Prefix { job_id, coinbase_id, flags, target_byte, ntime, nonce } =
            Prefix::read(&mut r)?;
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
        out.put_u8(SUBMIT_POW);
        out.put_u8(self.job_id);
        out.put_u8(self.coinbase_id);
        let flag = |set: bool, bit: u8| if set { bit } else { 0 };
        out.put_u8(
            flag(self.is_block, FLAG_IS_BLOCK)
                | flag(self.subsidy_only, FLAG_SUBSIDY_ONLY)
                | flag(self.quickdiff, FLAG_QUICKDIFF)
                | FLAG_BLAKE2B,
        );
        out.put_u8(self.target_byte);
        out.put_u32_le(self.ntime);
        out.put_u32_le(self.nonce);
        out.put_u32_le(self.version);
        out.put_u8(self.extranonce.len() as u8);
        out.put_slice(&self.extranonce);
        out.put_slice(self.username.as_bytes());
        out.put_u8(0);
        let mut reserved = [0u8; RESERVED_SIZE];
        if self.use_time_offset {
            reserved[0] |= RESERVED_USE_TIME_OFFSET;
        }
        out.put_slice(&reserved);
        if let Some(j) = &self.job {
            encode_job_section(&mut out, j);
        }
        if let Some(c) = &self.coinbase {
            encode_coinbase_section(&mut out, c);
        }
        encode_blake2b_section(&mut out, &self.blake2b);
        if let Some(slot) = self.abw_slot {
            out.put_u8(SECTION_ABW_SLOT);
            out.put_u8(slot);
        }
        out.put_u8(STRUCT_END);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal() -> PowSubmit {
        PowSubmit {
            job_id: 3,
            coinbase_id: 2,
            is_block: false,
            subsidy_only: false,
            quickdiff: false,
            target_byte: 14,
            ntime: 0x6543_2100,
            nonce: 0xdead_beef,
            version: 0x2000_0000,
            extranonce: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            username: "bc1qexample.worker1".to_string(),
            use_time_offset: false,
            job: None,
            coinbase: None,
            blake2b: Blake2bSection {
                sia_ntime: [0x11; 8],
                sia_nonce: [0x22; 8],
                time_on_wire: 0x6543_2100,
            },
            abw_slot: None,
        }
    }

    fn full() -> PowSubmit {
        let mut s = minimal();
        s.is_block = true;
        s.quickdiff = true;
        s.job = Some(JobSection {
            prev_hash: [0xaa; 32],
            target_byte_index: 42,
            nbits: [0xff, 0xff, 0x00, 0x1d],
            coinbaser_id: 7,
            height: 961_632,
            coinbase_value: 312_500_000,
            txn_count: 2100,
            txn_total_weight: 3_980_000,
            txn_total_size: 995_000,
            txn_total_sigops: 12_000,
            merkle_branches: vec![[0x11; 32], [0x22; 32], [0x33; 32]],
        });
        s.coinbase = Some(CoinbaseSection {
            coinbase_id: 2,
            coinb1: vec![0xab; 100],
            coinb2: vec![0xcd; 60],
        });
        s
    }

    #[test]
    fn roundtrips_minimal_and_full() {
        for s in [minimal(), full()] {
            let bytes = s.encode();
            assert_eq!(PowSubmit::decode(&bytes).unwrap(), s);
        }
    }

    #[test]
    fn ignores_trailing_padding() {
        let s = full();
        let mut bytes = s.encode();
        bytes.extend_from_slice(&[0x5a; 47]);
        assert_eq!(PowSubmit::decode(&bytes).unwrap(), s);
    }

    #[test]
    fn fixed_field_offsets_match_the_gateway() {
        let bytes = minimal().encode();
        assert_eq!(bytes[0], SUBMIT_POW);
        assert_eq!(bytes[1], 3);
        assert_eq!(bytes[2], 2);
        assert_eq!(bytes[3], FLAG_BLAKE2B, "the C gateway sets 0x08 on every submit");
        assert_eq!(bytes[4], 14);
        assert_eq!(&bytes[5..9], &0x6543_2100u32.to_le_bytes());
        assert_eq!(&bytes[9..13], &0xdead_beefu32.to_le_bytes());
        assert_eq!(&bytes[13..17], &0x2000_0000u32.to_le_bytes());
        assert_eq!(bytes[17], 12);
        assert_eq!(&bytes[18..30], &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        assert_eq!(&bytes[30..49], b"bc1qexample.worker1");
        assert_eq!(bytes[49], 0);
        assert_eq!(&bytes[50..54], &[0u8; 4]);
        assert_eq!(bytes[54], SECTION_BLAKE2B);
        assert_eq!(bytes[54 + 23], STRUCT_END);
    }

    #[test]
    fn a_share_without_the_blake2b_section_is_refused() {
        let bytes = minimal().encode();
        let mut upstream = bytes[..54].to_vec();
        upstream.push(STRUCT_END);
        assert_eq!(PowSubmit::decode(&upstream), Err(Error::MissingBlake2bSection));
    }

    #[test]
    fn blake2b_section_layout_is_exact() {
        let mut s = minimal();
        s.extranonce = vec![0x33; EXTRANONCE_SIZE];
        let bytes = s.encode();
        let at = bytes.len() - 24;
        assert_eq!(bytes[bytes.len() - 1], STRUCT_END);
        let sec = &bytes[at..bytes.len() - 1];
        assert_eq!(sec.len(), 23);
        assert_eq!(sec[0], SECTION_BLAKE2B);
        assert_eq!(sec[1], BLAKE2B_ALGORITHM);
        assert_eq!(&sec[2..10], &[0x11; 8]);
        assert_eq!(&sec[10..18], &[0x22; 8]);
        assert_eq!(sec[18], BLAKE2B_TIME);
        assert_eq!(&sec[19..23], &0x6543_2100u32.to_le_bytes());
        assert_eq!(PowSubmit::decode(&bytes).unwrap(), s);

        s.use_time_offset = true;
        let bytes = s.encode();
        assert_eq!(bytes[at - 4] & RESERVED_USE_TIME_OFFSET, RESERVED_USE_TIME_OFFSET);
        assert_eq!(PowSubmit::decode(&bytes).unwrap(), s);
    }

    #[test]
    fn the_prefix_of_a_share_that_does_not_decode_is_still_read() {
        let bytes = minimal().encode();
        let mut truncated = bytes.clone();
        truncated.truncate(56);
        assert!(matches!(PowSubmit::decode(&truncated), Err(Error::Truncated(_))));
        assert_eq!(PowSubmit::prefix(&truncated), Some((3, 14, 0xdead_beef)));
        assert_eq!(PowSubmit::prefix(&bytes[..12]), None, "shorter than the prefix");
        assert_eq!(PowSubmit::prefix(&bytes[..13]), Some((3, 14, 0xdead_beef)));
    }

    #[test]
    fn decodes_the_c_gateways_section_order_at_its_offsets() {
        let mut msg = vec![SUBMIT_POW, 0, 2, FLAG_BLAKE2B, 1];
        msg.extend_from_slice(&0x1413_1211u32.to_le_bytes());
        msg.extend_from_slice(&0x0403_0201u32.to_le_bytes());
        msg.extend_from_slice(&0x2000_0000u32.to_le_bytes());
        msg.push(12);
        msg.extend_from_slice(&[0u8; 12]);
        msg.extend_from_slice(b"pool\0");
        msg.extend_from_slice(&[RESERVED_USE_TIME_OFFSET, 0, 0, 0]);
        assert_eq!(msg.len(), 39);
        msg.extend_from_slice(&[SECTION_BLAKE2B, BLAKE2B_ALGORITHM]);
        msg.extend_from_slice(&0x1817_1615_1413_1211u64.to_le_bytes());
        msg.extend_from_slice(&0x0807_0605_0403_0201u64.to_le_bytes());
        assert_eq!(msg.len(), 57);
        msg.push(BLAKE2B_TIME);
        msg.extend_from_slice(&0x6553_412fu32.to_le_bytes());
        assert_eq!(msg.len(), 62);
        msg.extend_from_slice(&[SECTION_ABW_SLOT, 0]);
        assert_eq!(msg.len(), 64);
        msg.push(SECTION_JOB);
        let mut prev_hash = [0u8; 32];
        prev_hash[0] = 0xa0;
        msg.extend_from_slice(&prev_hash);
        msg.extend_from_slice(&4u16.to_le_bytes());
        msg.extend_from_slice(&[0xb0, 0, 0, 0]);
        msg.push(0);
        msg.extend_from_slice(&100u32.to_le_bytes());
        msg.extend_from_slice(&5_000_000_000u64.to_le_bytes());
        msg.extend_from_slice(&[0u8; 16]);
        msg.push(0);
        assert_eq!(msg.len(), 133);
        msg.extend_from_slice(&[SECTION_COINBASE, 2, 1, 0, 1, 0, 0xc0, 0xd0, STRUCT_END]);
        assert_eq!(msg.len(), 142);

        let s = PowSubmit::decode(&msg).unwrap();
        assert_eq!((s.job_id, s.coinbase_id, s.target_byte), (0, 2, 1));
        assert!(!s.is_block && !s.subsidy_only && !s.quickdiff);
        assert_eq!((s.ntime, s.nonce, s.version), (0x1413_1211, 0x0403_0201, 0x2000_0000));
        assert_eq!(s.username, "pool");
        assert!(s.use_time_offset);
        assert_eq!(s.blake2b.time_fields(), (0x1413_1211, 0x1817_1615));
        assert_eq!(s.blake2b.nonce_fields(), (0x0403_0201, 0x0807_0605));
        assert_eq!(s.blake2b.time_on_wire, 0x6553_412f);
        assert_eq!(s.abw_slot, Some(0));
        let job = s.job.as_ref().unwrap();
        assert_eq!((job.prev_hash, job.target_byte_index, job.height), (prev_hash, 4, 100));
        assert_eq!(
            (job.nbits, job.coinbaser_id, job.coinbase_value),
            ([0xb0, 0, 0, 0], 0, 5_000_000_000)
        );
        let cb = s.coinbase.as_ref().unwrap();
        assert_eq!((cb.coinbase_id, &cb.coinb1[..], &cb.coinb2[..]), (2, &[0xc0][..], &[0xd0][..]));
        assert_eq!(s.ntime, s.blake2b.time_fields().0);
        assert_eq!(s.nonce, s.blake2b.nonce_fields().0);
    }

    #[test]
    fn the_sia_fields_split_into_four_header_fields() {
        let b = Blake2bSection {
            sia_ntime: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            sia_nonce: [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18],
            time_on_wire: 0,
        };
        assert_eq!(b.nonce_fields(), (0x1413_1211, 0x1817_1615), "nNonce, m_nonce2");
        assert_eq!(b.time_fields(), (0x0403_0201, 0x0807_0605), "m_time_offset, m_nonce3");
    }

    #[test]
    fn flags_decode_independently() {
        for (is_block, subsidy_only, quickdiff) in
            [(true, false, false), (false, true, false), (false, false, true), (true, true, true)]
        {
            let mut s = minimal();
            s.is_block = is_block;
            s.subsidy_only = subsidy_only;
            s.quickdiff = quickdiff;
            let d = PowSubmit::decode(&s.encode()).unwrap();
            assert_eq!(
                (d.is_block, d.subsidy_only, d.quickdiff),
                (is_block, subsidy_only, quickdiff)
            );
        }
    }

    #[test]
    fn rejects_bad_extranonce_size() {
        let mut bytes = minimal().encode();
        bytes[17] = 8;
        assert_eq!(PowSubmit::decode(&bytes), Err(Error::BadExtranonceSize(8)));
        for n in [0u8, 8, 11, 13, 16, 255] {
            let mut bytes = minimal().encode();
            bytes[17] = n;
            assert_eq!(PowSubmit::decode(&bytes), Err(Error::BadExtranonceSize(n)), "size {n}");
        }
    }

    #[test]
    fn the_header_extranonce_is_the_twelve_left_padded() {
        let twelve: Vec<u8> = (1..=12u8).collect();
        let field = header_extranonce(&twelve).unwrap();
        assert_eq!(&field[..EXTRANONCE_V2_PAD], &[0u8; 4]);
        assert_eq!(&field[EXTRANONCE_V2_PAD..], &twelve[..]);
        assert_eq!(header_extranonce(&[0u8; 16]), None, "the field is not what is sent");
        assert_eq!(header_extranonce(&[]), None);
    }

    #[test]
    fn the_section_from_a_header_splits_back_into_its_fields() {
        let h = HeaderV2 {
            nonce: 0x1413_1211,
            nonce2: 0x1817_1615,
            time_offset: 0x0403_0201,
            nonce3: 0x0807_0605,
            time: 1_700_000_100,
            flags: crate::header::FLAG_USE_TIME_OFFSET,
            ..Default::default()
        };
        let b = Blake2bSection::from_header(&h);
        assert_eq!(b.nonce_fields(), (h.nonce, h.nonce2));
        assert_eq!(b.time_fields(), (h.time_offset, h.nonce3));
        assert_eq!(b.time_on_wire, h.time_on_wire());
        assert_eq!(b.time_on_wire.wrapping_add(h.time_offset), h.time);
        let mut field = [0u8; EXTRANONCE_SIZE_V2];
        field[4..].copy_from_slice(&[9u8; 12]);
        let twelve = share_extranonce(&field).unwrap();
        assert_eq!(header_extranonce(&twelve), Some(field));
        field[0] = 1;
        assert_eq!(share_extranonce(&field), None);
    }

    #[test]
    fn every_job_id_byte_decodes() {
        for id in [0u8, 7, 8, 200, 255] {
            let mut bytes = minimal().encode();
            bytes[1] = id;
            assert_eq!(PowSubmit::decode(&bytes).unwrap().job_id, id);
        }
    }

    #[test]
    fn rejects_truncated_message() {
        let bytes = full().encode();
        for cut in [10, 30, 50, bytes.len() - 5] {
            assert!(PowSubmit::decode(&bytes[..cut]).is_err(), "should fail at {cut}");
        }
    }

    #[test]
    fn difficulty_from_target_byte() {
        let mut s = minimal();
        s.target_byte = 14;
        assert_eq!(s.difficulty(), 16384);
        s.target_byte = 0;
        assert_eq!(s.difficulty(), 1);
    }

    #[test]
    fn coinbase_assembly_places_extranonce() {
        let c = CoinbaseSection { coinbase_id: 0, coinb1: vec![0xaa, 0xbb], coinb2: vec![0xcc] };
        let tx = c.assemble(&[9u8; EXTRANONCE_SIZE]);
        assert_eq!(tx.len(), 2 + EXTRANONCE_SIZE + 1);
        assert_eq!(&tx[..2], &[0xaa, 0xbb]);
        assert_eq!(&tx[2..14], &[9u8; 12]);
        assert_eq!(tx[14], 0xcc);
    }
}
