use crate::cursor::{Cursor, Truncated};
use crate::datum::codes::wire_codes;

pub use super::messages::client_subcmd::VALIDATION;

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

pub use super::framing::STRUCT_END;
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
        out.push(VALIDATION);
        out.push(response::PARENT_FETCH);
        out.push(self.job_index);
        out.push(self.status.code());
        out.extend_from_slice(&self.parent_hash);
        out.extend_from_slice(&(self.block.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.block);
        out.push(STRUCT_END);
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
        out.extend_from_slice(&self.txn_count.to_le_bytes());
        if self.txn_count == 0 {
            return out;
        }
        for id in &self.short_ids {
            out.extend_from_slice(&(*id as u32).to_le_bytes());
            out.extend_from_slice(&((*id >> 32) as u16).to_le_bytes());
        }
        if let Some(x) = self.crosscheck {
            out.extend_from_slice(&x);
        }
        out.push(STRUCT_END);
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
        out.extend_from_slice(&(self.txns.len() as u16).to_le_bytes());
        for tx in &self.txns {
            encode_txn_size(&mut out, tx.len());
            out.extend_from_slice(tx);
        }
        out.push(STRUCT_END);
        out
    }
}

/// A transaction's length in a bundle: a little-endian u16 followed by its high byte.
const TXN_SIZE_LEN: usize = 3;

fn decode_txn_size(c: &mut Cursor<'_>) -> Result<usize, Error> {
    let b: [u8; TXN_SIZE_LEN] = c.arr("txn size")?;
    Ok(usize::from(u16::from_le_bytes([b[0], b[1]])) | (usize::from(b[2]) << 16))
}

fn encode_txn_size(out: &mut Vec<u8>, len: usize) {
    out.extend_from_slice(&(len as u16).to_le_bytes());
    out.push((len >> 16) as u8);
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
    let k0 = u64::from_le_bytes(key[..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(key[8..].try_into().unwrap());
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
