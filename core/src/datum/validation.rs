use crate::cursor::{Cursor, Truncated};

pub use super::messages::client_subcmd::VALIDATION;

pub mod request {
    pub const SHORT_TXN_LIST: u8 = 0x10;
    pub const TXNS: u8 = 0x11;
    /// The template's transactions without the coinbase transaction.
    pub const BLOCK_TXNS: u8 = 0x12;
}

pub mod response {
    pub const SHORT_TXN_LIST: u8 = 0x90;
    pub const TXNS: u8 = 0x91;
    pub const BLOCK_TXNS: u8 = 0x92;
}

pub use super::framing::STRUCT_END;
pub const JOB_INDEX_INVALID: u8 = 0xFF;
pub const MAX_SHORT_LIST_TXNS: u16 = 16383;
pub const MAX_TXN_SIZE: usize = 0xff_ffff;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Ok,
    JobEmpty,
    NoTemplate,
    TooManyTxns,
    BadJobIndex,
    BadRequest,
    Unknown(u8),
}

impl Status {
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x01 => Status::Ok,
            0xF0 => Status::JobEmpty,
            0xF1 => Status::NoTemplate,
            0xF2 => Status::TooManyTxns,
            0xF3 => Status::BadJobIndex,
            0xF4 => Status::BadRequest,
            other => Status::Unknown(other),
        }
    }

    pub fn to_byte(self) -> u8 {
        match self {
            Status::Ok => 0x01,
            Status::JobEmpty => 0xF0,
            Status::NoTemplate => 0xF1,
            Status::TooManyTxns => 0xF2,
            Status::BadJobIndex => 0xF3,
            Status::BadRequest => 0xF4,
            Status::Unknown(b) => b,
        }
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Status::Ok => write!(f, "ok"),
            Status::JobEmpty => write!(f, "job slot empty"),
            Status::NoTemplate => write!(f, "no block template"),
            Status::TooManyTxns => write!(f, "too many transactions for a short list"),
            Status::BadJobIndex => write!(f, "bad job index"),
            Status::BadRequest => write!(f, "bad transaction request"),
            Status::Unknown(b) => write!(f, "unknown status {b:#04x}"),
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
        Error::Truncated(t.0)
    }
}

pub fn request_short_txn_list(job_index: u8) -> Vec<u8> {
    vec![VALIDATION, request::SHORT_TXN_LIST, job_index]
}

pub fn request_txns(job_index: u8, indices: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + indices.len() * 2);
    out.push(VALIDATION);
    out.push(request::TXNS);
    out.push(job_index);
    out.extend_from_slice(&(indices.len() as u16).to_le_bytes());
    for i in indices {
        out.extend_from_slice(&i.to_le_bytes());
    }
    out
}

pub fn request_block_txns(job_index: u8) -> Vec<u8> {
    vec![VALIDATION, request::BLOCK_TXNS, job_index]
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShortTxnList {
    pub job_index: u8,
    pub status: Status,
    pub txn_count: u16,
    pub short_ids: Vec<u64>,
    pub crosscheck: Option<[u8; 32]>,
}

pub const CROSSCHECK_SEED: [u8; 32] = [
    0xA3, 0x4F, 0xC1, 0x9C, 0x5E, 0x88, 0x76, 0x12, 0x0A, 0x79, 0x3E, 0xF1, 0x6C, 0x93, 0x54, 0xAF,
    0xB8, 0x1D, 0xE8, 0x5A, 0x20, 0xC7, 0x94, 0x38, 0x6F, 0xA1, 0x02, 0xD9, 0x4A, 0x7B, 0xF0, 0x11,
];

impl ShortTxnList {
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut c = body_of(data, response::SHORT_TXN_LIST)?;
        let job_index = c.u8("job index")?;
        let status = Status::from_byte(c.u8("status")?);
        if status != Status::Ok {
            return Ok(ShortTxnList {
                job_index,
                status,
                txn_count: 0,
                short_ids: Vec::new(),
                crosscheck: None,
            });
        }
        let txn_count = c.u16("txn count")?;
        if txn_count == 0 {
            return Ok(ShortTxnList {
                job_index,
                status,
                txn_count: 0,
                short_ids: Vec::new(),
                crosscheck: None,
            });
        }
        let ids = c.take(txn_count as usize * 6, "short ids")?;
        let short_ids = ids
            .as_chunks::<6>()
            .0
            .iter()
            .map(|c| {
                let low = u32::from_le_bytes(c[..4].try_into().unwrap());
                let high = u16::from_le_bytes(c[4..].try_into().unwrap());
                u64::from(low) | (u64::from(high) << 32)
            })
            .collect();
        let crosscheck: [u8; 32] = c.arr("crosscheck")?;
        if c.u8("terminator")? != STRUCT_END {
            return Err(Error::MissingTerminator);
        }
        Ok(ShortTxnList { job_index, status, txn_count, short_ids, crosscheck: Some(crosscheck) })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out =
            vec![VALIDATION, response::SHORT_TXN_LIST, self.job_index, self.status.to_byte()];
        if self.status != Status::Ok {
            return out;
        }
        out.extend_from_slice(&self.txn_count.to_le_bytes());
        if self.txn_count == 0 {
            return out;
        }
        for id in &self.short_ids {
            out.extend_from_slice(&(*id as u32).to_le_bytes());
            out.extend_from_slice(&(((*id >> 32) & 0xffff) as u16).to_le_bytes());
        }
        if let Some(x) = self.crosscheck {
            out.extend_from_slice(&x);
        }
        out.push(STRUCT_END);
        out
    }

    /// Whether the list names exactly `hashes`: the transactions' witness hashes (GBT `hash`,
    /// the gateway's `hash_bin`), not their txids, in internal byte order.
    pub fn matches(&self, hashes: &[[u8; 32]], key: &[u8; 16]) -> bool {
        if self.status != Status::Ok || self.txn_count as usize != hashes.len() {
            return false;
        }
        if hashes.is_empty() {
            return self.short_ids.is_empty() && self.crosscheck.is_none();
        }
        let expected: Vec<u64> = hashes.iter().map(|h| short_id(h, key)).collect();
        self.short_ids == expected && self.crosscheck == Some(crosscheck(hashes))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxnBundle {
    /// The response selector, 0x91 or 0x92.
    pub selector: u8,
    pub job_index: u8,
    pub status: Status,
    pub txns: Vec<Vec<u8>>,
}

impl TxnBundle {
    pub fn decode(data: &[u8], selector: u8) -> Result<Self, Error> {
        let mut c = body_of(data, selector)?;
        let job_index = c.u8("job index")?;
        let status = Status::from_byte(c.u8("status")?);
        if status != Status::Ok {
            return Ok(TxnBundle { selector, job_index, status, txns: Vec::new() });
        }
        let stated = usize::from(c.u16("txn count")?);

        let mut txns = Vec::with_capacity(stated.min(1024));
        for _ in 0..stated {
            let size = c.take(3, "txn size")?;
            let len = usize::from(u16::from_le_bytes(size[..2].try_into().unwrap()))
                | (usize::from(size[2]) << 16);
            let tx = c.take(len, "txn").map_err(|_| Error::BadTxnSize)?;
            txns.push(tx.to_vec());
        }
        if txns.len() != stated {
            return Err(Error::TxnCountMismatch { stated, found: txns.len() });
        }
        if c.u8("terminator")? != STRUCT_END {
            return Err(Error::MissingTerminator);
        }
        Ok(TxnBundle { selector, job_index, status, txns })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![VALIDATION, self.selector, self.job_index, self.status.to_byte()];
        if self.status != Status::Ok {
            return out;
        }
        out.extend_from_slice(&(self.txns.len() as u16).to_le_bytes());
        for tx in &self.txns {
            out.extend_from_slice(&(tx.len() as u16).to_le_bytes());
            out.push((tx.len() >> 16) as u8);
            out.extend_from_slice(tx);
        }
        out.push(STRUCT_END);
        out
    }
}

/// A cursor past the optional 0x50 prefix and the selector, which must be `want`.
fn body_of(data: &[u8], want: u8) -> Result<Cursor<'_>, Error> {
    let mut c = Cursor::new(data);
    c.skip_if(VALIDATION);
    let got = c.u8("response selector")?;
    if got != want {
        return Err(Error::WrongMessage { want, got });
    }
    Ok(c)
}

/// The first 16 bytes of the two ed25519 public signing keys XORed together, then every byte
/// XORed with 0x55 (`datum_protocol.c`). Both ends derive it, so neither sends it.
pub fn short_id_key(gateway_pk: &[u8; 32], pool_pk: &[u8; 32]) -> [u8; 16] {
    let mut key = [0u8; 16];
    for (j, k) in key.iter_mut().enumerate() {
        *k = (gateway_pk[j] ^ pool_pk[j]) ^ 0x55;
    }
    key
}

/// The low 48 bits of the siphash, serialized as a u32 then a u16.
pub fn short_id(hash: &[u8; 32], key: &[u8; 16]) -> u64 {
    siphash24(key, hash) & 0x0000_ffff_ffff_ffff
}

/// Every hash (the transactions' witness hashes, as in `matches`) XORed into a fixed seed, so
/// both ends compare a whole list in one 32-byte comparison.
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
        assert_eq!(request_short_txn_list(3), vec![0x50, 0x10, 3]);
        assert_eq!(request_block_txns(7), vec![0x50, 0x12, 7]);
        let r = request_txns(2, &[0, 5, 300]);
        assert_eq!(&r[..3], &[0x50, 0x11, 2]);
        assert_eq!(&r[3..5], &3u16.to_le_bytes());
        assert_eq!(&r[5..7], &0u16.to_le_bytes());
        assert_eq!(&r[7..9], &5u16.to_le_bytes());
        assert_eq!(&r[9..11], &300u16.to_le_bytes());
        assert_eq!(r.len(), 11);
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
    fn short_list_roundtrips_and_ignores_padding() {
        let l = sample_list();
        let bytes = l.encode();
        assert_eq!(bytes.len(), 4 + 2 + 18 + 32 + 1);
        assert_eq!(ShortTxnList::decode(&bytes).unwrap(), l);
        let mut padded = bytes.clone();
        padded.extend_from_slice(&[0x5a; 77]);
        assert_eq!(ShortTxnList::decode(&padded).unwrap(), l);
        assert_eq!(ShortTxnList::decode(&bytes[1..]).unwrap(), l);
    }

    #[test]
    fn short_list_accepts_the_shapes_without_a_terminator() {
        let empty = ShortTxnList {
            job_index: 1,
            status: Status::Ok,
            txn_count: 0,
            short_ids: vec![],
            crosscheck: None,
        };
        let bytes = empty.encode();
        assert_eq!(bytes, vec![0x50, 0x90, 1, 0x01, 0x00, 0x00]);
        assert_eq!(ShortTxnList::decode(&bytes).unwrap(), empty);

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
            let bytes = e.encode();
            assert_eq!(bytes.len(), 4);
            assert_eq!(ShortTxnList::decode(&bytes).unwrap(), e);
        }
    }

    #[test]
    fn short_list_matches_the_pools_own_template() {
        let hashes = [ramp(0), ramp(0x20), ramp(0x40)];
        let l = sample_list();
        assert!(l.matches(&hashes, &KEY));

        let other = [ramp(0), ramp(0x20), ramp(0x60)];
        assert!(!l.matches(&other, &KEY));
        let reordered = [ramp(0x20), ramp(0), ramp(0x40)];
        assert!(!l.matches(&reordered, &KEY));
        assert!(!l.matches(&hashes[..2], &KEY));
        assert!(!l.matches(&hashes, &[0u8; 16]));

        let mut altered = l.clone();
        altered.crosscheck = Some([0u8; 32]);
        assert!(!altered.matches(&hashes, &KEY));

        let empty = ShortTxnList {
            job_index: 0,
            status: Status::Ok,
            txn_count: 0,
            short_ids: vec![],
            crosscheck: None,
        };
        assert!(empty.matches(&[], &KEY));
    }

    #[test]
    fn short_list_rejects_malformed_messages() {
        let bytes = sample_list().encode();
        for cut in [1, 3, 5, 10, bytes.len() - 1] {
            assert!(ShortTxnList::decode(&bytes[..cut]).is_err(), "should fail at {cut}");
        }
        let mut no_end = bytes.clone();
        let n = no_end.len();
        no_end[n - 1] = 0x00;
        assert_eq!(ShortTxnList::decode(&no_end), Err(Error::MissingTerminator));

        assert_eq!(
            ShortTxnList::decode(&[0x50, 0x91, 0, 0x01]),
            Err(Error::WrongMessage { want: 0x90, got: 0x91 })
        );
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
