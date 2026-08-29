use crate::cursor::{Cursor, Truncated};
use crate::header::HeaderV2;

pub use super::messages::client_subcmd::SUBMIT_POW;
pub const SECTION_JOB: u8 = 0x01;
pub const SECTION_COINBASE: u8 = 0x02;
pub const SECTION_BLAKE2B: u8 = 0x03;
/// Sub-field markers inside the BLAKE2b section.
pub const BLAKE2B_ALGORITHM: u8 = 0x01;
pub const BLAKE2B_TIME: u8 = 0x04;
/// Bit 0 of the first reserved byte of the submit-POW message: set when the header's
/// `FLAG_USE_TIME_OFFSET` (m_flags bit 2) is set; the header bit itself is not sent. The
/// reserved bytes are where a header flag the pool needs goes; the ASIC profile is not sent
/// at all, because profile 0 is the only one either end produces.
pub const RESERVED_USE_TIME_OFFSET: u8 = 0x01;
pub use super::framing::STRUCT_END;
/// The extranonce bytes a share carries: extranonce1 then extranonce2.
///
/// The header's extranonce is a 16-byte field (`m_extranonce`) whose leading four bytes are
/// zero: the gateway's extranonce1 is eight bytes (`DATUM_HEADER_V2_EXTRANONCE1_SIZE`): four
/// zero bytes (`DATUM_HEADER_V2_EXTRANONCE_PAD`) then the four-byte session id. The share
/// sends the twelve that vary, in the field the upstream DATUM format sizes for them, and the
/// pool restores the padding.
pub const EXTRANONCE_SIZE: usize = 12;
/// The header field the twelve are restored into (`DATUM_HEADER_V2_EXTRANONCE_SIZE`).
pub const EXTRANONCE_SIZE_V2: usize = 16;
/// How many leading bytes of that field the gateway holds at zero.
pub const EXTRANONCE_V2_PAD: usize = EXTRANONCE_SIZE_V2 - EXTRANONCE_SIZE;
/// The coinbase index for subsidy-only work: the gateway's literal 255 (a comment in
/// `datum_stratum.h`; no named constant).
pub const COINBASE_ID_SUBSIDY_ONLY: u8 = 0xFF;
pub const MAX_JOBS: usize = 256;
/// The gateway's `merklebranches_bin[24][32]`.
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
    /// The share carries no 0x03 section: the upstream (SHA256d) DATUM format, which this
    /// pool does not verify.
    #[error("no BLAKE2b section")]
    MissingBlake2bSection,
}

impl From<Truncated> for Error {
    fn from(t: Truncated) -> Self {
        Error::Truncated(t.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobSection {
    pub prev_hash: [u8; 32],
    /// The index of the PoT byte in the coinbase transaction (the gateway's `target_pot_index`).
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

/// What the mining hardware controls, as `mining.submit` sent it.
///
/// The pool builds the header from this and the installed job (the 0x01 and 0x02 sections
/// the gateway sent) rather than receiving one, so every field the mining hardware does not
/// set is taken from the job and the pool's policy, and a share cannot supply a different
/// value for one. `sia_ntime` and `sia_nonce` are the raw eight-byte stratum fields,
/// spliced rather than parsed; in ASIC profile 0 they carry four header fields:
///
/// ```text
/// sia_nonce = nNonce (4, LE) || m_nonce2 (4, LE)
/// sia_ntime = m_time_offset (4, LE) || m_nonce3 (4, LE)
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Blake2bSection {
    pub sia_ntime: [u8; 8],
    pub sia_nonce: [u8; 8],
    /// The job's time, as the header's time field serializes it (Knots `GetTimeOnWire`); the
    /// block time is this plus `m_time_offset` when the time-offset flag is set. The hardware
    /// never changes it.
    pub time_on_wire: u32,
}

/// The 16-byte header field the share's twelve bytes restore into: the four the gateway
/// holds at zero, then what it sent.
pub fn header_extranonce(extranonce: &[u8]) -> Option<[u8; EXTRANONCE_SIZE_V2]> {
    if extranonce.len() != EXTRANONCE_SIZE {
        return None;
    }
    let mut out = [0u8; EXTRANONCE_SIZE_V2];
    out[EXTRANONCE_V2_PAD..].copy_from_slice(extranonce);
    Some(out)
}

/// The twelve bytes a share sends for a header's 16-byte extranonce field: `None` when the
/// four the gateway holds at zero are not zero. The inverse of `header_extranonce`.
pub fn share_extranonce(field: &[u8; EXTRANONCE_SIZE_V2]) -> Option<Vec<u8>> {
    if field[..EXTRANONCE_V2_PAD] != [0u8; EXTRANONCE_V2_PAD] {
        return None;
    }
    Some(field[EXTRANONCE_V2_PAD..].to_vec())
}

impl Blake2bSection {
    /// The section for a header in ASIC profile 0: the four nonce and time fields spliced
    /// into the two eight-byte Sia fields, and the time as the header serializes it. The
    /// inverse of `nonce_fields`, `time_fields` and `HeaderV2::time_on_wire`.
    pub fn from_header(h: &HeaderV2) -> Self {
        let mut sia_nonce = [0u8; 8];
        sia_nonce[..4].copy_from_slice(&h.nonce.to_le_bytes());
        sia_nonce[4..].copy_from_slice(&h.nonce2.to_le_bytes());
        let mut sia_ntime = [0u8; 8];
        sia_ntime[..4].copy_from_slice(&h.time_offset.to_le_bytes());
        sia_ntime[4..].copy_from_slice(&h.nonce3.to_le_bytes());
        Blake2bSection { sia_ntime, sia_nonce, time_on_wire: h.time_on_wire() }
    }

    /// `nNonce` and `m_nonce2`, in that order.
    pub fn nonce_fields(&self) -> (u32, u32) {
        (le32(&self.sia_nonce[..4]), le32(&self.sia_nonce[4..]))
    }

    /// `m_time_offset` and `m_nonce3`, in that order.
    pub fn time_fields(&self) -> (u32, u32) {
        (le32(&self.sia_ntime[..4]), le32(&self.sia_ntime[4..]))
    }
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes(b.try_into().expect("four bytes"))
}

/// A share as the gateway submits it (0x27). The fixed fields are the upstream DATUM
/// layout; `ntime`, `nonce` and `version` are carried in it but the header the pool builds
/// takes its time and nonces from `blake2b` (the 0x03 section, which every share must carry)
/// and its version from `version` with the v2 flag stripped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PowSubmit {
    pub job_id: u8,
    pub coinbase_id: u8,
    pub is_block: bool,
    pub subsidy_only: bool,
    pub quickdiff: bool,
    pub target_byte: u8,
    /// The upstream format's 32-bit time field; the gateway writes `blake2b.time_on_wire`.
    pub ntime: u32,
    /// The upstream format's nonce field; the gateway writes the header's `nNonce`, which
    /// `blake2b.sia_nonce` also carries.
    pub nonce: u32,
    pub version: u32,
    pub extranonce: Vec<u8>,
    pub username: String,
    /// The header's time-offset selector, carried in the reserved bytes. Set, the block time
    /// is the job time plus `m_time_offset`; clear, `m_time_offset` is an additional nonce
    /// field and the block time is the job time.
    pub use_time_offset: bool,
    pub job: Option<JobSection>,
    pub coinbase: Option<CoinbaseSection>,
    pub blake2b: Blake2bSection,
}

impl PowSubmit {
    /// The target byte index this share claims: its own job section's when it carries
    /// one, otherwise the installed `job`'s.
    pub fn target_byte_index_of(&self, job: &JobSection) -> u16 {
        self.job.as_ref().map_or(job.target_byte_index, |j| j.target_byte_index)
    }

    pub fn difficulty(&self) -> u64 {
        // Masked because this is also called on shares that have not been checked yet,
        // where `verify::reconstruct` rejects a target byte of 64 or more.
        1u64 << (self.target_byte & 63)
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
        // Four bytes the gateway reserves. Bit 0 of the first is the time-offset selector.
        let reserved = r.take(4, "reserved")?;
        let use_time_offset = reserved[0] & RESERVED_USE_TIME_OFFSET != 0;

        let mut job = None;
        let mut coinbase = None;
        let mut blake2b = None;
        loop {
            match r.u8("section marker")? {
                STRUCT_END => break,
                SECTION_JOB => {
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
                    job = Some(JobSection {
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
                    });
                }
                SECTION_COINBASE => {
                    let coinbase_id = r.u8("coinbase section id")?;
                    let len1 = r.u16("coinb1 len")? as usize;
                    let len2 = r.u16("coinb2 len")? as usize;
                    let coinb1 = r.take(len1, "coinb1")?.to_vec();
                    let coinb2 = r.take(len2, "coinb2")?.to_vec();
                    coinbase = Some(CoinbaseSection { coinbase_id, coinb1, coinb2 });
                }
                SECTION_BLAKE2B => {
                    if r.u8("algorithm")? != BLAKE2B_ALGORITHM {
                        return Err(Error::BadBlake2bSection);
                    }
                    let sia_ntime: [u8; 8] = r.arr("sia ntime")?;
                    let sia_nonce: [u8; 8] = r.arr("sia nonce")?;
                    if r.u8("time marker")? != BLAKE2B_TIME {
                        return Err(Error::BadBlake2bSection);
                    }
                    let time_on_wire = r.u32("time on wire")?;
                    blake2b = Some(Blake2bSection { sia_ntime, sia_nonce, time_on_wire });
                }
                other => return Err(Error::UnknownSection(other)),
            }
        }
        let blake2b = blake2b.ok_or(Error::MissingBlake2bSection)?;

        Ok(PowSubmit {
            job_id,
            coinbase_id,
            is_block: flags & 1 != 0,
            subsidy_only: flags & 2 != 0,
            quickdiff: flags & 4 != 0,
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
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.push(SUBMIT_POW);
        out.push(self.job_id);
        out.push(self.coinbase_id);
        out.push(
            (self.is_block as u8)
                | ((self.subsidy_only as u8) << 1)
                | ((self.quickdiff as u8) << 2),
        );
        out.push(self.target_byte);
        out.extend_from_slice(&self.ntime.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.extend_from_slice(&self.version.to_le_bytes());
        out.push(self.extranonce.len() as u8);
        out.extend_from_slice(&self.extranonce);
        out.extend_from_slice(self.username.as_bytes());
        out.push(0);
        let mut reserved = [0u8; 4];
        if self.use_time_offset {
            reserved[0] |= RESERVED_USE_TIME_OFFSET;
        }
        out.extend_from_slice(&reserved);
        if let Some(j) = &self.job {
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
        if let Some(c) = &self.coinbase {
            out.push(SECTION_COINBASE);
            out.push(c.coinbase_id);
            out.extend_from_slice(&(c.coinb1.len() as u16).to_le_bytes());
            out.extend_from_slice(&(c.coinb2.len() as u16).to_le_bytes());
            out.extend_from_slice(&c.coinb1);
            out.extend_from_slice(&c.coinb2);
        }
        let b = &self.blake2b;
        out.push(SECTION_BLAKE2B);
        out.push(BLAKE2B_ALGORITHM);
        out.extend_from_slice(&b.sia_ntime);
        out.extend_from_slice(&b.sia_nonce);
        out.push(BLAKE2B_TIME);
        out.extend_from_slice(&b.time_on_wire.to_le_bytes());
        out.push(STRUCT_END);
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
        assert_eq!(bytes[3], 0);
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

    /// A share in the upstream format, without the 0x03 section, is refused: the pool builds
    /// no SHA256d header.
    #[test]
    fn a_share_without_the_blake2b_section_is_refused() {
        let bytes = minimal().encode();
        let mut upstream = bytes[..54].to_vec();
        upstream.push(STRUCT_END);
        assert_eq!(PowSubmit::decode(&upstream), Err(Error::MissingBlake2bSection));
    }

    /// The section is a fixed 23 bytes. Asserted here because both ends hardcode these
    /// offsets, and because it is the format the gateway fork emits (`datum_protocol.c`, the 0x03
    /// section).
    #[test]
    fn blake2b_section_layout_is_exact() {
        let mut s = minimal();
        s.extranonce = vec![0x33; EXTRANONCE_SIZE];
        let bytes = s.encode();
        let at = bytes.len() - 24; // the section, then the 0xFE terminator
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

        // The one header flag the pool needs is carried in the reserved bytes instead.
        s.use_time_offset = true;
        let bytes = s.encode();
        assert_eq!(bytes[at - 4] & RESERVED_USE_TIME_OFFSET, RESERVED_USE_TIME_OFFSET);
        assert_eq!(PowSubmit::decode(&bytes).unwrap(), s);
    }

    /// The four header fields the two eight-byte Sia fields carry, in the order profile 0 lays
    /// out.
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
        // Twelve is the only size: the header's 16-byte field less the four zero bytes.
        for n in [0u8, 8, 11, 13, 16, 255] {
            let mut bytes = minimal().encode();
            bytes[17] = n;
            assert_eq!(PowSubmit::decode(&bytes), Err(Error::BadExtranonceSize(n)), "size {n}");
        }
    }

    /// The pool restores the four bytes the gateway holds at zero, so what the header
    /// commits to is the twelve sent, with the four zero bytes in front of them.
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
