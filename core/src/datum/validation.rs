use crate::cursor::{Cursor, Truncated};
use crate::datum::codes::wire_codes;
use bytes::BufMut as _;

use super::messages::client_subcmd::VALIDATION;

pub mod request {
    pub const SHORT_TXN_LIST: u8 = 0x10;
    pub const TXNS: u8 = 0x11;
    pub const BLOCK_TXNS: u8 = 0x12;
    pub const PARENT_FETCH: u8 = 0x14;
}

pub mod response {
    pub const SHORT_TXN_LIST: u8 = 0x90;
    pub const TXNS: u8 = 0x91;
    pub const BLOCK_TXNS: u8 = 0x92;
    pub const PARENT_FETCH: u8 = 0x94;
}

use super::framing::STRUCT_END;
pub const JOB_INDEX_INVALID: u8 = 0xFF;
pub const MAX_SHORT_LIST_TXNS: u16 = 16383;

wire_codes! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Status: u8 {
        Ok = 0x01,
        JobEmpty = 0xF0,
        NoTemplate = 0xF1,
        TooManyTxns = 0xF2,
        BadJobIndex = 0xF3,
        BadRequest = 0xF4,
    }
    unknown Unknown;
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok => write!(f, "ok"),
            Self::JobEmpty => write!(f, "job slot empty"),
            Self::NoTemplate => write!(f, "no block template"),
            Self::TooManyTxns => write!(f, "too many transactions for a short list"),
            Self::BadJobIndex => write!(f, "bad job index"),
            Self::BadRequest => write!(f, "bad transaction request"),
            Self::Unknown(b) => write!(f, "unknown status {b:#04x}"),
        }
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("truncated validation message: {0}")]
    Truncated(&'static str),
    #[error("expected response {want:#04x}, got {got:#04x}")]
    WrongMessage { want: u8, got: u8 },
    #[error("transaction size exceeds the message")]
    BadTxnSize,
    #[error("missing 0xFE terminator")]
    MissingTerminator,
    #[error("message states {stated} transactions but holds {found}")]
    TxnCountMismatch { stated: usize, found: usize },
}

impl From<Truncated> for Error {
    fn from(t: Truncated) -> Self {
        Self::Truncated(t.0)
    }
}

pub const SELECTOR_AT: usize = 1;
pub const JOB_INDEX_AT: usize = 2;
pub const REQUEST_HEADER_LEN: usize = JOB_INDEX_AT + 1;
pub const PARENT_FETCH_REQUEST_LEN: usize = REQUEST_HEADER_LEN + crate::bitcoin::HASH_SIZE;

pub fn request_block_txns(job_index: u8) -> Vec<u8> {
    vec![VALIDATION, request::BLOCK_TXNS, job_index]
}

wire_codes! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ParentStatus: u8 {
        Success = 0x01,
        JobMismatch = 0xF0,
        Busy = 0xF6,
        Unavailable = 0xF7,
        RpcFailed = 0xF8,
    }
    unknown Unknown;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParentFetchReply {
    pub job_index: u8,
    pub status: ParentStatus,
    pub parent_hash: [u8; 32],
    pub block: Vec<u8>,
}

pub const PARENT_FETCH_REPLY_OVERHEAD: usize =
    (REQUEST_HEADER_LEN + 1) + crate::bitcoin::HASH_SIZE + size_of::<u32>() + 1;

pub const MAX_PARENT_FETCH_BLOCK: usize =
    super::framing::MAX_CMD_DATA_SIZE as usize - (PARENT_FETCH_REPLY_OVERHEAD + 1);

impl ParentFetchReply {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PARENT_FETCH_REPLY_OVERHEAD + self.block.len());
        out.put_u8(VALIDATION);
        out.put_u8(response::PARENT_FETCH);
        out.put_u8(self.job_index);
        out.put_u8(self.status.code());
        out.put_slice(&self.parent_hash);
        out.put_u32_le(self.block.len() as u32);
        out.put_slice(&self.block);
        out.put_u8(STRUCT_END);
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShortTxnList {
    pub job_index: u8,
    pub status: Status,
    pub txn_count: u16,
    pub short_ids: Vec<u64>,
    pub crosscheck: Option<[u8; 32]>,
}

pub const SHORT_ID_SIZE: usize = size_of::<u32>() + size_of::<u16>();
const SHORT_ID_MASK: u64 = (1u64 << (8 * SHORT_ID_SIZE)) - 1;

pub const CROSSCHECK_SEED: [u8; 32] = [
    0xA3, 0x4F, 0xC1, 0x9C, 0x5E, 0x88, 0x76, 0x12, 0x0A, 0x79, 0x3E, 0xF1, 0x6C, 0x93, 0x54, 0xAF,
    0xB8, 0x1D, 0xE8, 0x5A, 0x20, 0xC7, 0x94, 0x38, 0x6F, 0xA1, 0x02, 0xD9, 0x4A, 0x7B, 0xF0, 0x11,
];

impl ShortTxnList {
    pub fn empty(job_index: u8, status: Status) -> Self {
        Self { job_index, status, txn_count: 0, short_ids: Vec::new(), crosscheck: None }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out =
            vec![VALIDATION, response::SHORT_TXN_LIST, self.job_index, self.status.code()];
        if self.status != Status::Ok {
            return out;
        }
        out.put_u16_le(self.txn_count);
        if self.txn_count == 0 {
            return out;
        }
        for id in &self.short_ids {
            out.put_slice(&id.to_le_bytes()[..SHORT_ID_SIZE]);
        }
        if let Some(x) = self.crosscheck {
            out.put_slice(&x);
        }
        out.put_u8(STRUCT_END);
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxnBundle {
    pub selector: u8,
    pub job_index: u8,
    pub status: Status,
    pub txns: Vec<Vec<u8>>,
}

impl TxnBundle {
    pub fn empty(selector: u8, job_index: u8, status: Status) -> Self {
        Self { selector, job_index, status, txns: Vec::new() }
    }

    pub fn decode(data: &[u8], selector: u8) -> Result<Self, Error> {
        let mut c = body_of(data, selector)?;
        let job_index = c.u8("job index")?;
        let status = Status::from_code(c.u8("status")?);
        if status != Status::Ok {
            return Ok(Self::empty(selector, job_index, status));
        }
        let stated = usize::from(c.u16("txn count")?);

        let mut txns = Vec::with_capacity(stated.min(1024));
        for _ in 0..stated {
            let len = decode_txn_size(&mut c)?;
            let tx = c.take(len, "txn").map_err(|_| Error::BadTxnSize)?;
            txns.push(tx.to_vec());
        }
        if txns.len() != stated {
            return Err(Error::TxnCountMismatch { stated, found: txns.len() });
        }
        if c.u8("terminator")? != STRUCT_END {
            return Err(Error::MissingTerminator);
        }
        Ok(Self { selector, job_index, status, txns })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![VALIDATION, self.selector, self.job_index, self.status.code()];
        if self.status != Status::Ok {
            return out;
        }
        out.put_u16_le(self.txns.len() as u16);
        for tx in &self.txns {
            encode_txn_size(&mut out, tx.len());
            out.put_slice(tx);
        }
        out.put_u8(STRUCT_END);
        out
    }
}

const TXN_SIZE_LEN: usize = 3;

fn decode_txn_size(c: &mut Cursor<'_>) -> Result<usize, Error> {
    let b: [u8; TXN_SIZE_LEN] = c.arr("txn size")?;
    Ok(usize::from(u16::from_le_bytes([b[0], b[1]])) | (usize::from(b[2]) << 16))
}

fn encode_txn_size(out: &mut Vec<u8>, len: usize) {
    out.put_u16_le(len as u16);
    out.put_u8((len >> 16) as u8);
}

fn body_of(data: &[u8], want: u8) -> Result<Cursor<'_>, Error> {
    let mut c = Cursor::new(data);
    c.skip_if(VALIDATION);
    let got = c.u8("response selector")?;
    if got != want {
        return Err(Error::WrongMessage { want, got });
    }
    Ok(c)
}

pub fn short_id_key(gateway_pk: &[u8; 32], pool_pk: &[u8; 32]) -> [u8; 16] {
    let mut key = [0u8; 16];
    for (j, k) in key.iter_mut().enumerate() {
        *k = (gateway_pk[j] ^ pool_pk[j]) ^ 0x55;
    }
    key
}

pub fn short_id(hash: &[u8; 32], key: &[u8; 16]) -> u64 {
    siphash24(key, hash) & SHORT_ID_MASK
}

pub fn crosscheck(hashes: &[[u8; 32]]) -> [u8; 32] {
    let mut x = CROSSCHECK_SEED;
    for h in hashes {
        for (a, b) in x.iter_mut().zip(h.iter()) {
            *a ^= b;
        }
    }
    x
}

pub fn siphash24(key: &[u8; 16], data: &[u8]) -> u64 {
    let [k0, k1] = key.as_chunks::<8>().0 else { unreachable!("16 bytes hold two words") };
    let (k0, k1) = (u64::from_le_bytes(*k0), u64::from_le_bytes(*k1));
    let mut v0 = k0 ^ 0x736f_6d65_7073_6575;
    let mut v1 = k1 ^ 0x646f_7261_6e64_6f6d;
    let mut v2 = k0 ^ 0x6c79_6765_6e65_7261;
    let mut v3 = k1 ^ 0x7465_6462_7974_6573;

    let (chunks, tail) = data.as_chunks::<8>();
    for c in chunks {
        let m = u64::from_le_bytes(*c);
        v3 ^= m;
        double_round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
    }
    let mut b = (data.len() as u64) << 56;
    for (i, byte) in tail.iter().enumerate() {
        b |= u64::from(*byte) << (8 * i);
    }
    v3 ^= b;
    double_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= b;
    v2 ^= 0xff;
    double_round(&mut v0, &mut v1, &mut v2, &mut v3);
    double_round(&mut v0, &mut v1, &mut v2, &mut v3);
    (v0 ^ v1) ^ (v2 ^ v3)
}

fn half_round(a: &mut u64, b: &mut u64, c: &mut u64, d: &mut u64, e: u32, f: u32) {
    *a = a.wrapping_add(*b);
    *c = c.wrapping_add(*d);
    *b = b.rotate_left(e) ^ *a;
    *d = d.rotate_left(f) ^ *c;
    *a = a.rotate_left(32);
}

fn double_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    half_round(v0, v1, v2, v3, 13, 16);
    half_round(v2, v1, v0, v3, 17, 21);
    half_round(v0, v1, v2, v3, 13, 16);
    half_round(v2, v1, v0, v3, 17, 21);
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    fn ramp(start: u8) -> [u8; 32] {
        let mut d = [0u8; 32];
        for (i, b) in d.iter_mut().enumerate() {
            *b = start.wrapping_add(i as u8);
        }
        d
    }

    #[test]
    fn siphash_matches_the_gateway() {
        assert_eq!(siphash24(&KEY, &ramp(0x00)), 0x7127_512f_72f2_7cce);
        assert_eq!(siphash24(&KEY, &ramp(0x20)), 0xc46d_4c33_58ae_89a5);
        assert_eq!(siphash24(&KEY, &ramp(0x40)), 0x27bd_5ecb_84e5_6c87);
        assert_eq!(siphash24(&KEY, &ramp(0x60)), 0x1d82_9164_c5ef_ca0b);
        assert_eq!(siphash24(&KEY, &[0u8; 32]), 0x8990_d3e4_2994_96f4);
        assert_eq!(siphash24(&KEY, &[0xffu8; 32]), 0xe104_1d47_f898_e431);
        assert_eq!(siphash24(&[0u8; 16], &[0u8; 32]), 0x6c37_e103_dfa2_827d);
        let mut swapped = KEY;
        swapped.rotate_left(8);
        assert_ne!(siphash24(&swapped, &ramp(0)), 0x7127_512f_72f2_7cce);
    }

    #[test]
    fn short_id_keeps_48_bits() {
        let h = ramp(0);
        assert_eq!(short_id(&h, &KEY), 0x7127_512f_72f2_7cce & 0xffff_ffff_ffff);
        assert_eq!(short_id(&h, &KEY) >> 48, 0);
    }

    #[test]
    fn short_id_key_derivation() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        assert_eq!(short_id_key(&a, &b), [0x11 ^ 0x22 ^ 0x55; 16]);
        assert_eq!(short_id_key(&a, &b), short_id_key(&b, &a));
    }

    #[test]
    fn crosscheck_is_a_running_xor_from_the_seed() {
        assert_eq!(crosscheck(&[]), CROSSCHECK_SEED);
        let h = [0xaau8; 32];
        let mut expected = CROSSCHECK_SEED;
        for b in expected.iter_mut() {
            *b ^= 0xaa;
        }
        assert_eq!(crosscheck(&[h]), expected);
        assert_eq!(crosscheck(&[h, h]), CROSSCHECK_SEED);
    }

    #[test]
    fn request_layouts() {
        let r = request_block_txns(7);
        assert_eq!(r, vec![0x50, 0x12, 7]);
        assert_eq!(r[SELECTOR_AT], request::BLOCK_TXNS);
        assert_eq!(r[JOB_INDEX_AT], 7);
        assert_eq!(r.len(), REQUEST_HEADER_LEN);
        assert_eq!(PARENT_FETCH_REQUEST_LEN, REQUEST_HEADER_LEN + 32);
    }

    fn sample_list() -> ShortTxnList {
        let hashes = [ramp(0), ramp(0x20), ramp(0x40)];
        ShortTxnList {
            job_index: 4,
            status: Status::Ok,
            txn_count: 3,
            short_ids: hashes.iter().map(|h| short_id(h, &KEY)).collect(),
            crosscheck: Some(crosscheck(&hashes)),
        }
    }

    #[test]
    fn short_list_encodes_at_the_c_offsets() {
        let l = sample_list();
        let bytes = l.encode();
        assert_eq!(bytes.len(), 4 + 2 + 3 * SHORT_ID_SIZE + 32 + 1);
        assert_eq!(&bytes[..4], &[0x50, response::SHORT_TXN_LIST, 4, Status::Ok.code()]);
        assert_eq!(&bytes[4..6], &3u16.to_le_bytes());
        for (i, id) in l.short_ids.iter().enumerate() {
            let at = 6 + i * SHORT_ID_SIZE;
            assert_eq!(&bytes[at..at + SHORT_ID_SIZE], &id.to_le_bytes()[..SHORT_ID_SIZE]);
        }
        assert_eq!(&bytes[24..56], &l.crosscheck.unwrap());
        assert_eq!(bytes[56], STRUCT_END);
    }

    #[test]
    fn short_list_encodes_the_shapes_without_a_terminator() {
        let empty = ShortTxnList {
            job_index: 1,
            status: Status::Ok,
            txn_count: 0,
            short_ids: vec![],
            crosscheck: None,
        };
        assert_eq!(empty.encode(), vec![0x50, 0x90, 1, 0x01, 0x00, 0x00]);

        for status in
            [Status::JobEmpty, Status::NoTemplate, Status::TooManyTxns, Status::BadJobIndex]
        {
            let e = ShortTxnList {
                job_index: JOB_INDEX_INVALID,
                status,
                txn_count: 0,
                short_ids: vec![],
                crosscheck: None,
            };
            assert_eq!(e.encode(), vec![0x50, 0x90, JOB_INDEX_INVALID, status.code()]);
        }
    }

    fn sample_bundle(selector: u8) -> TxnBundle {
        TxnBundle {
            selector,
            job_index: 6,
            status: Status::Ok,
            txns: vec![vec![0xab; 10], vec![0xcd; 300], vec![]],
        }
    }

    #[test]
    fn txn_bundle_roundtrips_both_selectors() {
        for selector in [response::TXNS, response::BLOCK_TXNS] {
            let b = sample_bundle(selector);
            let bytes = b.encode();
            assert_eq!(TxnBundle::decode(&bytes, selector).unwrap(), b);
            let mut padded = bytes.clone();
            padded.extend_from_slice(&[0x33; 50]);
            assert_eq!(TxnBundle::decode(&padded, selector).unwrap(), b);
        }
    }

    #[test]
    fn txn_size_prefix_is_three_bytes_little_endian() {
        let b = TxnBundle {
            selector: response::BLOCK_TXNS,
            job_index: 0,
            status: Status::Ok,
            txns: vec![vec![0x11; 0x01_2345]],
        };
        let bytes = b.encode();
        assert_eq!(&bytes[6..9], &[0x45, 0x23, 0x01]);
        assert_eq!(TxnBundle::decode(&bytes, response::BLOCK_TXNS).unwrap(), b);
    }

    #[test]
    fn txn_bundle_carries_error_statuses() {
        for status in
            [Status::JobEmpty, Status::NoTemplate, Status::BadJobIndex, Status::BadRequest]
        {
            let e = TxnBundle { selector: response::TXNS, job_index: 2, status, txns: vec![] };
            let bytes = e.encode();
            assert_eq!(bytes.len(), 4);
            assert_eq!(TxnBundle::decode(&bytes, response::TXNS).unwrap(), e);
        }
    }

    #[test]
    fn txn_bundle_rejects_malformed_messages() {
        let bytes = sample_bundle(response::BLOCK_TXNS).encode();
        for cut in [1, 3, 6, 20, bytes.len() - 1] {
            assert!(TxnBundle::decode(&bytes[..cut], response::BLOCK_TXNS).is_err(), "at {cut}");
        }
        let mut oversize = bytes.clone();
        oversize[6] = 0xff;
        oversize[7] = 0xff;
        oversize[8] = 0xff;
        assert_eq!(TxnBundle::decode(&oversize, response::BLOCK_TXNS), Err(Error::BadTxnSize));
        let mut miscount = bytes.clone();
        miscount[4] = 9;
        assert!(TxnBundle::decode(&miscount, response::BLOCK_TXNS).is_err());
    }
}
