//! The job validation exchange (0x50). The pool asks a gateway for the short transaction list of a
//! job, for named transactions from it, for all of them, which is how a block is assembled, or for
//! the parent block; the gateway answers from the template the job was built on. The short ids are
//! SipHash-2-4 under a key both sides derive from their signing keys.

use super::{Error, STRUCT_END, open_message, read_terminator};
use crate::datum::codes::wire_codes;
use crate::reader::ByteReader;
use crate::siphash::siphash24;
use bytes::BufMut as _;

/// The validation message's subcommand: the pool's request and the gateway's response carry
/// the same byte, which `request` and `response` below then select within.
pub const SUBCMD: u8 = 0x50;

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

pub const JOB_INDEX_INVALID: u8 = 0xFF;
pub const MAX_SHORT_LIST_TXNS: u16 = 16383;

wire_codes! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum TxnListStatus: u8 {
        Ok = 0x01,
        JobEmpty = 0xF0,
        NoTemplate = 0xF1,
        TooManyTxns = 0xF2,
        BadJobIndex = 0xF3,
        BadRequest = 0xF4,
    }
    unknown Unknown;
}

impl std::fmt::Display for TxnListStatus {
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

pub const SELECTOR_AT: usize = 1;
pub const JOB_INDEX_AT: usize = 2;
pub const REQUEST_HEADER_LEN: usize = JOB_INDEX_AT + 1;
pub const PARENT_FETCH_REQUEST_LEN: usize = REQUEST_HEADER_LEN + crate::bitcoin::HASH_SIZE;

pub fn request_block_txns(job_index: u8) -> Vec<u8> {
    vec![SUBCMD, request::BLOCK_TXNS, job_index]
}

wire_codes! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ParentFetchStatus: u8 {
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
    pub status: ParentFetchStatus,
    pub parent_hash: [u8; 32],
    pub block: Vec<u8>,
}

pub(crate) const PARENT_FETCH_REPLY_OVERHEAD: usize =
    (REQUEST_HEADER_LEN + 1) + crate::bitcoin::HASH_SIZE + size_of::<u32>() + 1;

pub const MAX_PARENT_FETCH_BLOCK_LEN: usize = crate::datum::channel::MAX_PLAINTEXT_LEN
    - PARENT_FETCH_REPLY_OVERHEAD
    - crate::datum::framing::MAX_MINING_PAD_LEN;

impl ParentFetchReply {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PARENT_FETCH_REPLY_OVERHEAD + self.block.len());
        out.put_u8(SUBCMD);
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
    pub status: TxnListStatus,
    pub short_ids: Vec<u64>,
    pub crosscheck: Option<[u8; 32]>,
}

pub(crate) const SHORT_ID_SIZE: usize = size_of::<u32>() + size_of::<u16>();
const SHORT_ID_MASK: u64 = (1u64 << (8 * SHORT_ID_SIZE)) - 1;

pub(crate) const CROSSCHECK_SEED: [u8; 32] = [
    0xA3, 0x4F, 0xC1, 0x9C, 0x5E, 0x88, 0x76, 0x12, 0x0A, 0x79, 0x3E, 0xF1, 0x6C, 0x93, 0x54, 0xAF,
    0xB8, 0x1D, 0xE8, 0x5A, 0x20, 0xC7, 0x94, 0x38, 0x6F, 0xA1, 0x02, 0xD9, 0x4A, 0x7B, 0xF0, 0x11,
];

impl ShortTxnList {
    pub fn empty(job_index: u8, status: TxnListStatus) -> Self {
        Self { job_index, status, short_ids: Vec::new(), crosscheck: None }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![SUBCMD, response::SHORT_TXN_LIST, self.job_index, self.status.code()];
        if self.status != TxnListStatus::Ok {
            return out;
        }
        out.put_u16_le(self.short_ids.len() as u16);
        if self.short_ids.is_empty() {
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
pub struct TxnList {
    pub selector: u8,
    pub job_index: u8,
    pub status: TxnListStatus,
    pub txns: Vec<Vec<u8>>,
}

impl TxnList {
    pub fn empty(selector: u8, job_index: u8, status: TxnListStatus) -> Self {
        Self { selector, job_index, status, txns: Vec::new() }
    }

    pub fn decode(data: &[u8], selector: u8) -> Result<Self, Error> {
        let mut c = body_of(data, selector)?;
        let job_index = c.u8("job index")?;
        let status = TxnListStatus::from_code(c.u8("status")?);
        if status != TxnListStatus::Ok {
            return Ok(Self::empty(selector, job_index, status));
        }
        let stated = usize::from(c.u16("txn count")?);

        let mut txns = Vec::with_capacity(stated.min(1024));
        for _ in 0..stated {
            let len = decode_txn_size(&mut c)?;
            txns.push(c.take(len, "txn")?.to_vec());
        }
        read_terminator(&mut c)?;
        Ok(Self { selector, job_index, status, txns })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![SUBCMD, self.selector, self.job_index, self.status.code()];
        if self.status != TxnListStatus::Ok {
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

/// The bytes of the size before each transaction of a transaction list reply.
pub const TXN_SIZE_LEN: usize = 3;

/// The bytes of a transaction list reply outside its transactions: the subcommand, selector,
/// job index and status, the two-byte count, and the terminator.
const TXN_LIST_REPLY_OVERHEAD: usize = (REQUEST_HEADER_LEN + 1) + size_of::<u16>() + 1;

/// The most bytes the transactions of one transaction list reply may take, each counted with
/// its `TXN_SIZE_LEN`-byte size: the largest plaintext a channel frame carries, less the
/// reply's other bytes and the most pad the gateway appends to a mining message. A reply with
/// more cannot be sent in one frame.
pub const MAX_TXN_LIST_TXN_BYTES: usize = crate::datum::channel::MAX_PLAINTEXT_LEN
    - TXN_LIST_REPLY_OVERHEAD
    - crate::datum::framing::MAX_MINING_PAD_LEN;

fn decode_txn_size(c: &mut ByteReader<'_>) -> Result<usize, Error> {
    let b: [u8; TXN_SIZE_LEN] = c.arr("txn size")?;
    Ok(usize::from(u16::from_le_bytes([b[0], b[1]])) | (usize::from(b[2]) << 16))
}

fn encode_txn_size(out: &mut Vec<u8>, len: usize) {
    out.put_u16_le(len as u16);
    out.put_u8((len >> 16) as u8);
}

fn body_of(data: &[u8], want: u8) -> Result<ByteReader<'_>, Error> {
    let mut c = open_message(data, SUBCMD)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::ramp;

    const KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

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

    fn sample_short_list() -> ShortTxnList {
        let hashes = [ramp(0), ramp(0x20), ramp(0x40)];
        ShortTxnList {
            job_index: 4,
            status: TxnListStatus::Ok,
            short_ids: hashes.iter().map(|h| short_id(h, &KEY)).collect(),
            crosscheck: Some(crosscheck(&hashes)),
        }
    }

    #[test]
    fn short_list_encodes_at_the_c_offsets() {
        let l = sample_short_list();
        let bytes = l.encode();
        assert_eq!(bytes.len(), 4 + 2 + 3 * SHORT_ID_SIZE + 32 + 1);
        assert_eq!(&bytes[..4], &[0x50, response::SHORT_TXN_LIST, 4, TxnListStatus::Ok.code()]);
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
            status: TxnListStatus::Ok,
            short_ids: vec![],
            crosscheck: None,
        };
        assert_eq!(empty.encode(), vec![0x50, 0x90, 1, 0x01, 0x00, 0x00]);

        for status in [
            TxnListStatus::JobEmpty,
            TxnListStatus::NoTemplate,
            TxnListStatus::TooManyTxns,
            TxnListStatus::BadJobIndex,
        ] {
            let e = ShortTxnList {
                job_index: JOB_INDEX_INVALID,
                status,
                short_ids: vec![],
                crosscheck: None,
            };
            assert_eq!(e.encode(), vec![0x50, 0x90, JOB_INDEX_INVALID, status.code()]);
        }
    }

    fn sample_txn_list(selector: u8) -> TxnList {
        TxnList {
            selector,
            job_index: 6,
            status: TxnListStatus::Ok,
            txns: vec![vec![0xab; 10], vec![0xcd; 300], vec![]],
        }
    }

    #[test]
    fn txn_list_roundtrips_both_selectors() {
        for selector in [response::TXNS, response::BLOCK_TXNS] {
            let b = sample_txn_list(selector);
            let bytes = b.encode();
            assert_eq!(TxnList::decode(&bytes, selector).unwrap(), b);
            let mut padded = bytes.clone();
            padded.extend_from_slice(&[0x33; 50]);
            assert_eq!(TxnList::decode(&padded, selector).unwrap(), b);
        }
    }

    #[test]
    fn txn_size_prefix_is_three_bytes_little_endian() {
        let b = TxnList {
            selector: response::BLOCK_TXNS,
            job_index: 0,
            status: TxnListStatus::Ok,
            txns: vec![vec![0x11; 0x01_2345]],
        };
        let bytes = b.encode();
        assert_eq!(&bytes[6..9], &[0x45, 0x23, 0x01]);
        assert_eq!(TxnList::decode(&bytes, response::BLOCK_TXNS).unwrap(), b);
    }

    #[test]
    fn a_txn_list_at_its_byte_bound_fills_a_frame_with_the_largest_pad() {
        let at_bound = TxnList {
            selector: response::TXNS,
            job_index: 0,
            status: TxnListStatus::Ok,
            txns: vec![vec![0x11; MAX_TXN_LIST_TXN_BYTES - TXN_SIZE_LEN]],
        };
        assert_eq!(
            at_bound.encode().len() + crate::datum::framing::MAX_MINING_PAD_LEN,
            crate::datum::channel::MAX_PLAINTEXT_LEN
        );
    }

    #[test]
    fn txn_list_carries_error_statuses() {
        for status in [
            TxnListStatus::JobEmpty,
            TxnListStatus::NoTemplate,
            TxnListStatus::BadJobIndex,
            TxnListStatus::BadRequest,
        ] {
            let e = TxnList { selector: response::TXNS, job_index: 2, status, txns: vec![] };
            let bytes = e.encode();
            assert_eq!(bytes.len(), 4);
            assert_eq!(TxnList::decode(&bytes, response::TXNS).unwrap(), e);
        }
    }

    #[test]
    fn txn_list_rejects_malformed_messages() {
        let bytes = sample_txn_list(response::BLOCK_TXNS).encode();
        for cut in [1, 3, 6, 20, bytes.len() - 1] {
            assert!(TxnList::decode(&bytes[..cut], response::BLOCK_TXNS).is_err(), "at {cut}");
        }
        let mut oversize = bytes.clone();
        oversize[6] = 0xff;
        oversize[7] = 0xff;
        oversize[8] = 0xff;
        assert!(matches!(
            TxnList::decode(&oversize, response::BLOCK_TXNS),
            Err(Error::Truncated(_))
        ));
        let mut miscount = bytes.clone();
        miscount[4] = 9;
        assert!(TxnList::decode(&miscount, response::BLOCK_TXNS).is_err());
    }
}
