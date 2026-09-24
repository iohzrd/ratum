//! The share a gateway submits (0x27) and the job, coinbase and BLAKE2b sections it carries. A
//! section is sent once per connection and reused by every later share on the job.
//! `PowSubmit::header` rebuilds the header the share was mined on, which is how the pool reaches
//! the hash the gateway computed.

use super::{Error, STRUCT_END, abw, client_subcmd::SUBMIT_POW, open_message};
use crate::header::{self, BlockHeaderV2, SIA_WORDS_LEN, XorKey};
use crate::reader::ByteReader;
use bytes::BufMut as _;

pub(crate) const SECTION_JOB: u8 = 0x01;
pub(crate) const SECTION_COINBASE: u8 = 0x02;
pub(crate) const SECTION_BLAKE2B: u8 = 0x03;
pub(crate) const SECTION_ABW_SLOT: u8 = 0x05;
pub(crate) const BLAKE2B_ALGORITHM: u8 = 0x01;
pub(crate) const BLAKE2B_TIME: u8 = 0x04;
pub(crate) const FLAG_IS_BLOCK: u8 = 0x01;
pub(crate) const FLAG_SUBSIDY_ONLY: u8 = 0x02;
pub(crate) const FLAG_QUICKDIFF: u8 = 0x04;
pub(crate) const FLAG_BLAKE2B: u8 = 0x08;
pub(crate) const RESERVED_USE_TIME_OFFSET: u8 = 0x01;
pub const EXTRANONCE_SIZE: usize = 12;
pub const HEADER_EXTRANONCE_SIZE: usize = 16;
pub const HEADER_EXTRANONCE_PAD: usize = HEADER_EXTRANONCE_SIZE - EXTRANONCE_SIZE;
pub(crate) const RESERVED_SIZE: usize = 4;
pub const COINBASE_ID_SUBSIDY_ONLY: u8 = 0xFF;
pub const MAX_JOBS: usize = 256;
/// The largest coinbase transaction a share carries, coinb1 and coinb2 together. The section
/// writes each part as a `u16` length, which would allow 65535; this limit holds
/// `MAX_COINBASER_OUTPUTS` P2WPKH outputs and the C gateway's `MAX_DICTATED_COINBASE_SIZE`
/// (32000), and at four weight units a byte costs a sixth of an RDTS block.
pub const MAX_COINBASE_SECTION_LEN: usize = 32768;
pub const MAX_MERKLE_BRANCHES: usize = 24;
pub const MAX_USERNAME_LEN: usize = 384;

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

/// What a share on a job commits to, computed the same way by the gateway that builds the
/// work and the pool that verifies it.
impl JobSection {
    /// The coinbase transaction: the section assembled with a zero extranonce (the header
    /// carries the miner's) and `target_byte` written at the job's target byte index. None
    /// when the index is outside the transaction.
    pub fn coinbase_tx(&self, cb: &CoinbaseSection, target_byte: u8) -> Option<Vec<u8>> {
        let mut tx = cb.assemble(&[0u8; EXTRANONCE_SIZE]);
        *tx.get_mut(usize::from(self.target_byte_index))? = target_byte;
        Some(tx)
    }

    /// The merkle root over `coinbase_tx` and the job's transactions; a subsidy-only block
    /// holds the coinbase alone.
    pub fn merkle_root(&self, coinbase_tx: &[u8], subsidy_only: bool) -> [u8; 32] {
        let branches: &[[u8; 32]] = if subsidy_only { &[] } else { &self.merkle_branches };
        crate::bitcoin::merkle_root_from_branches(&crate::bitcoin::sha256d(coinbase_tx), branches)
    }

    /// The header fields the job and its coinbase decide, with the nonces, extranonce, time
    /// offset, flags and XOR key zero. `abw` sets the XOR key mask clear bits `target_byte`
    /// sizes, for work under an anti-block-withholding assignment. None when the transaction
    /// count does not fit the header's 16-bit count.
    pub fn header(
        &self,
        version: i32,
        time: u32,
        merkle_root: [u8; 32],
        subsidy_only: bool,
        target_byte: u8,
        abw: bool,
    ) -> Option<BlockHeaderV2> {
        let tx_count = if subsidy_only { 1 } else { u64::from(self.txn_count) + 1 };
        Some(BlockHeaderV2 {
            version,
            prev_block: self.prev_hash,
            merkle_root,
            time,
            bits: u32::from_le_bytes(self.nbits),
            txcount: u16::try_from(tx_count).ok()?,
            xor_key_mask_clear_bits: if abw { abw::clear_bits(target_byte) } else { 0 },
            height: self.height as i32,
            ..Default::default()
        })
    }
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
    pub sia_ntime: [u8; SIA_WORDS_LEN],
    pub sia_nonce: [u8; SIA_WORDS_LEN],
    pub time_on_wire: u32,
}

pub fn header_extranonce(extranonce: &[u8; EXTRANONCE_SIZE]) -> [u8; HEADER_EXTRANONCE_SIZE] {
    let mut out = [0u8; HEADER_EXTRANONCE_SIZE];
    out[HEADER_EXTRANONCE_PAD..].copy_from_slice(extranonce);
    out
}

pub fn share_extranonce(field: &[u8; HEADER_EXTRANONCE_SIZE]) -> Option<[u8; EXTRANONCE_SIZE]> {
    let (pad, extranonce) = field.split_at(HEADER_EXTRANONCE_PAD);
    if pad != [0u8; HEADER_EXTRANONCE_PAD] {
        return None;
    }
    extranonce.try_into().ok()
}

/// The two words a sia field packs, the inverse of `header::sia_words`.
fn sia_halves(field: &[u8; SIA_WORDS_LEN]) -> (u32, u32) {
    let (low, high) = field.split_at(header::SIA_WORD_LEN);
    let le32 = |b: &[u8]| u32::from_le_bytes(b.try_into().expect("four bytes"));
    (le32(low), le32(high))
}

/// Writes the sia fields into the header fields they carry: `sia_nonce` into `nonce` and
/// `nonce2`, `sia_ntime` into `time_offset` and `nonce3`. The inverse of
/// `Blake2bSection::from_header`.
pub fn set_sia_fields(
    h: &mut BlockHeaderV2,
    sia_ntime: &[u8; SIA_WORDS_LEN],
    sia_nonce: &[u8; SIA_WORDS_LEN],
) {
    (h.nonce, h.nonce2) = sia_halves(sia_nonce);
    (h.time_offset, h.nonce3) = sia_halves(sia_ntime);
}

impl Blake2bSection {
    pub fn from_header(h: &BlockHeaderV2) -> Self {
        Self {
            sia_ntime: header::sia_words(h.time_offset, h.nonce3),
            sia_nonce: header::sia_words(h.nonce, h.nonce2),
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

fn decode_job_section(r: &mut ByteReader<'_>) -> Result<JobSection, Error> {
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

fn decode_coinbase_section(r: &mut ByteReader<'_>) -> Result<CoinbaseSection, Error> {
    let coinbase_id = r.u8("coinbase section id")?;
    let len1 = r.u16("coinb1 len")? as usize;
    let len2 = r.u16("coinb2 len")? as usize;
    let coinb1 = r.take(len1, "coinb1")?.to_vec();
    let coinb2 = r.take(len2, "coinb2")?.to_vec();
    Ok(CoinbaseSection { coinbase_id, coinb1, coinb2 })
}

fn encode_coinbase_section(out: &mut Vec<u8>, c: &CoinbaseSection) {
    // What the pool enforces before installing a section, and stronger than each part
    // fitting its own u16 length: a longer part is written as a truncated length.
    debug_assert!(
        c.coinb1.len() + c.coinb2.len() <= MAX_COINBASE_SECTION_LEN,
        "coinbase over MAX_COINBASE_SECTION_LEN"
    );
    out.put_u8(SECTION_COINBASE);
    out.put_u8(c.coinbase_id);
    out.put_u16_le(c.coinb1.len() as u16);
    out.put_u16_le(c.coinb2.len() as u16);
    out.put_slice(&c.coinb1);
    out.put_slice(&c.coinb2);
}

fn decode_blake2b_section(r: &mut ByteReader<'_>) -> Result<Blake2bSection, Error> {
    if r.u8("algorithm")? != BLAKE2B_ALGORITHM {
        return Err(Error::BadBlake2bSection);
    }
    let sia_ntime: [u8; SIA_WORDS_LEN] = r.arr("sia ntime")?;
    let sia_nonce: [u8; SIA_WORDS_LEN] = r.arr("sia nonce")?;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharePrefix {
    pub job_id: u8,
    pub coinbase_id: u8,
    pub flags: u8,
    pub target_byte: u8,
    pub ntime: u32,
    pub nonce: u32,
}

impl Default for SharePrefix {
    /// The prefix a share whose bytes did not decode is answered under: the placeholder
    /// target byte, which the gateway reads as a difficulty the pool could not name, and
    /// zero in every other field.
    fn default() -> Self {
        Self {
            job_id: 0,
            coinbase_id: 0,
            flags: 0,
            target_byte: crate::datum::coinbase::TARGET_BYTE_PLACEHOLDER,
            ntime: 0,
            nonce: 0,
        }
    }
}

impl SharePrefix {
    /// The prefix and a reader past it.
    fn read(data: &[u8]) -> Result<(Self, ByteReader<'_>), Error> {
        let mut r = open_message(data, SUBMIT_POW)?;
        let prefix = Self {
            job_id: r.u8("job id")?,
            coinbase_id: r.u8("coinbase id")?,
            flags: r.u8("flags")?,
            target_byte: r.u8("target byte")?,
            ntime: r.u32("ntime")?,
            nonce: r.u32("nonce")?,
        };
        Ok((prefix, r))
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
    pub extranonce: [u8; EXTRANONCE_SIZE],
    pub username: String,
    pub use_time_offset: bool,
    pub job: Option<JobSection>,
    pub coinbase: Option<CoinbaseSection>,
    pub blake2b: Blake2bSection,
    pub abw_slot: Option<u8>,
}

impl PowSubmit {
    pub fn difficulty(&self) -> u64 {
        crate::target::difficulty_for_exponent(self.target_byte)
    }

    /// The block time the header carries: the time on the wire, plus the header's time
    /// offset when the share sets the time offset flag.
    pub fn block_time(&self) -> u32 {
        let b = &self.blake2b;
        if self.use_time_offset {
            let (time_offset, _) = b.time_fields();
            b.time_on_wire.wrapping_add(time_offset)
        } else {
            b.time_on_wire
        }
    }

    /// The header this share was mined on: `JobSection::header` with the share's version,
    /// time and nonces, the inverse of `Blake2bSection::from_header`. `merkle_root` is
    /// `JobSection::merkle_root` of the rebuilt coinbase and `abw_key` the slot key an
    /// anti-block-withholding session assigned. None when the job's transaction count does not
    /// fit the header's 16-bit count.
    pub fn header(
        &self,
        job: &JobSection,
        merkle_root: &[u8; 32],
        abw_key: Option<XorKey>,
    ) -> Option<BlockHeaderV2> {
        let mut h = job.header(
            (self.version & !header::V2_FLAG) as i32,
            self.block_time(),
            *merkle_root,
            self.subsidy_only,
            self.target_byte,
            abw_key.is_some(),
        )?;
        set_sia_fields(&mut h, &self.blake2b.sia_ntime, &self.blake2b.sia_nonce);
        h.extranonce = header_extranonce(&self.extranonce);
        if self.use_time_offset {
            h.flags = header::FLAG_USE_TIME_OFFSET;
        }
        h.xor_key = abw_key.unwrap_or_default();
        Some(h)
    }

    pub fn prefix(data: &[u8]) -> Option<SharePrefix> {
        SharePrefix::read(data).ok().map(|(prefix, _)| prefix)
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let (SharePrefix { job_id, coinbase_id, flags, target_byte, ntime, nonce }, mut r) =
            SharePrefix::read(data)?;
        let version = r.u32("version")?;
        let en_size = r.u8("extranonce size")?;
        if en_size as usize != EXTRANONCE_SIZE {
            return Err(Error::BadExtranonceSize(en_size));
        }
        let extranonce = r.arr("extranonce")?;

        let rest = r.rest();
        let nul = rest
            .iter()
            .take(MAX_USERNAME_LEN + 1)
            .position(|&b| b == 0)
            .ok_or(Error::BadUsername)?;
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
        out.put_u8(EXTRANONCE_SIZE as u8);
        out.put_slice(&self.extranonce);
        out.put_slice(self.username.as_bytes());
        out.put_u8(0);
        let mut reserved = [0u8; RESERVED_SIZE];
        if self.use_time_offset {
            reserved[0] |= RESERVED_USE_TIME_OFFSET;
        }
        out.put_slice(&reserved);
        // The C gateway's section order: BLAKE2b, the ABW slot, then the job and coinbase
        // sections the pool has not yet received. `decode` takes the sections in any order.
        encode_blake2b_section(&mut out, &self.blake2b);
        if let Some(slot) = self.abw_slot {
            out.put_u8(SECTION_ABW_SLOT);
            out.put_u8(slot);
        }
        if let Some(j) = &self.job {
            encode_job_section(&mut out, j);
        }
        if let Some(c) = &self.coinbase {
            encode_coinbase_section(&mut out, c);
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
            extranonce: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
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
        s.extranonce = [0x33; EXTRANONCE_SIZE];
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
        let prefix = PowSubmit::prefix(&truncated).unwrap();
        assert_eq!((prefix.job_id, prefix.target_byte, prefix.nonce), (3, 14, 0xdead_beef));
        assert_eq!(
            (prefix.coinbase_id, prefix.flags, prefix.ntime),
            (2, FLAG_BLAKE2B, 0x6543_2100)
        );
        assert_eq!(PowSubmit::prefix(&bytes[..12]), None, "shorter than the prefix");
        assert_eq!(PowSubmit::prefix(&bytes[..13]), Some(prefix));
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
        assert_eq!(s.encode(), msg, "and encodes the sections in the C gateway's order");
    }

    /// The encoder writes the C gateway's order; the decoder also takes the order this
    /// encoder wrote before it (job, coinbase, BLAKE2b, ABW slot).
    #[test]
    fn the_decoder_takes_the_sections_in_any_order() {
        let mut s = full();
        s.abw_slot = Some(9);
        let bytes = s.encode();
        let sections_at = bytes.len()
            - 1
            - (23 + 2)
            - (69 + 32 * 3)
            - (6 + s.coinbase.as_ref().map_or(0, |c| c.coinb1.len() + c.coinb2.len()));
        assert_eq!(bytes[sections_at], SECTION_BLAKE2B, "the BLAKE2b section comes first");
        let mut reordered = bytes[..sections_at].to_vec();
        encode_job_section(&mut reordered, s.job.as_ref().unwrap());
        encode_coinbase_section(&mut reordered, s.coinbase.as_ref().unwrap());
        encode_blake2b_section(&mut reordered, &s.blake2b);
        reordered.extend_from_slice(&[SECTION_ABW_SLOT, 9, STRUCT_END]);
        assert_eq!(reordered.len(), bytes.len());
        assert_eq!(PowSubmit::decode(&reordered).unwrap(), s);
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
        let twelve: [u8; EXTRANONCE_SIZE] = std::array::from_fn(|i| i as u8 + 1);
        let field = header_extranonce(&twelve);
        assert_eq!(&field[..HEADER_EXTRANONCE_PAD], &[0u8; 4]);
        assert_eq!(&field[HEADER_EXTRANONCE_PAD..], &twelve[..]);
    }

    #[test]
    fn the_section_from_a_header_splits_back_into_its_fields() {
        let h = BlockHeaderV2 {
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
        let mut field = [0u8; HEADER_EXTRANONCE_SIZE];
        field[4..].copy_from_slice(&[9u8; 12]);
        let twelve = share_extranonce(&field).unwrap();
        assert_eq!(header_extranonce(&twelve), field);
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

    #[test]
    fn a_share_rebuilds_the_header_its_section_was_taken_from() {
        let mut extranonce = [0u8; 16];
        extranonce[4..].copy_from_slice(&[7u8; 12]);
        let h = BlockHeaderV2 {
            version: 0x2000_0000,
            prev_block: [0xaa; 32],
            merkle_root: [0xbb; 32],
            time: 1_700_000_100,
            bits: 0x207f_ffff,
            nonce: 1,
            nonce2: 2,
            nonce3: 3,
            extranonce,
            time_offset: 4,
            txcount: 1,
            flags: crate::header::FLAG_USE_TIME_OFFSET,
            height: 21,
            ..Default::default()
        };
        let job = JobSection {
            prev_hash: h.prev_block,
            target_byte_index: 0,
            nbits: h.bits.to_le_bytes(),
            coinbaser_id: 0,
            height: 21,
            coinbase_value: 0,
            txn_count: 0,
            txn_total_weight: 0,
            txn_total_size: 0,
            txn_total_sigops: 0,
            merkle_branches: vec![],
        };
        let b = Blake2bSection::from_header(&h);
        let s = PowSubmit {
            subsidy_only: true,
            target_byte: 10,
            ntime: b.time_on_wire,
            nonce: h.nonce,
            version: crate::header::V2_FLAG | h.version as u32,
            extranonce: share_extranonce(&h.extranonce).unwrap(),
            use_time_offset: true,
            blake2b: b,
            ..minimal()
        };
        assert_eq!(s.header(&job, &h.merkle_root, None), Some(h.clone()));

        let key = [0x5a; 16];
        let masked = s.header(&job, &h.merkle_root, Some(key)).unwrap();
        assert_eq!(masked.xor_key, key);
        assert_eq!(masked.xor_key_mask_clear_bits, abw::clear_bits(10));

        let pooled = PowSubmit { subsidy_only: false, ..s.clone() };
        let with_txns = JobSection { txn_count: 2, ..job.clone() };
        assert_eq!(pooled.header(&with_txns, &h.merkle_root, None).unwrap().txcount, 3);
        assert_eq!(s.header(&with_txns, &h.merkle_root, None).unwrap().txcount, 1);
        let too_many = JobSection { txn_count: u32::MAX, ..job.clone() };
        assert_eq!(pooled.header(&too_many, &h.merkle_root, None), None);
    }
}
