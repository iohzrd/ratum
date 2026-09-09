use crate::cursor::{Cursor, Truncated};
use sha2::{Digest, Sha256};

pub mod opcode {
    pub const OP_0: u8 = 0x00;
    pub const OP_PUSHDATA1: u8 = 0x4c;
    pub const OP_PUSHDATA2: u8 = 0x4d;
    pub const OP_PUSHDATA4: u8 = 0x4e;
    pub const OP_1: u8 = 0x51;
    pub const OP_16: u8 = 0x60;
    pub const OP_RETURN: u8 = 0x6a;
    pub const OP_DUP: u8 = 0x76;
    pub const OP_EQUAL: u8 = 0x87;
    pub const OP_EQUALVERIFY: u8 = 0x88;
    pub const OP_HASH160: u8 = 0xa9;
    pub const OP_CHECKSIG: u8 = 0xac;
    pub const OP_CHECKSIGVERIFY: u8 = 0xad;
    pub const OP_CHECKMULTISIG: u8 = 0xae;
    pub const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;

    pub const MAX_DIRECT_PUSH: usize = OP_PUSHDATA1 as usize - 1;
    pub const MAX_DIRECT_PUSH_OPCODE: u8 = MAX_DIRECT_PUSH as u8;

    pub const OP_N_BASE: u8 = OP_1 - 1;
}

pub const HASH_SIZE: usize = 32;
pub const TX_VERSION_SIZE: usize = 4;
pub const OUTPOINT_SIZE: usize = HASH_SIZE + 4;
pub const SEQUENCE_SIZE: usize = 4;
pub const VALUE_SIZE: usize = 8;
pub const LOCK_TIME_SIZE: usize = 4;
pub const MIN_OUTPUT_SIZE: usize = VALUE_SIZE + 1;
const SEGWIT_MARKER_AND_FLAG: (u8, u8) = (0x00, 0x01);
const SEGWIT_MARKER_AND_FLAG_SIZE: usize = 2;
pub const WITNESS_SCALE_FACTOR: u64 = 4;

pub const NULL_OUTPOINT_INDEX: [u8; OUTPOINT_SIZE - HASH_SIZE] = [0xff; OUTPOINT_SIZE - HASH_SIZE];
pub const SEQUENCE_FINAL: [u8; SEQUENCE_SIZE] = [0xff; SEQUENCE_SIZE];

pub const MAX_OUTPUT_SCRIPT_SIZE: usize = 34;
pub const MAX_OUTPUT_DATA_SIZE: usize = 83;
pub const MAX_COMPACT_SIZE_LEN: usize = 1 + size_of::<u64>();

pub use opcode::OP_RETURN;

pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    Sha256::digest(first).into()
}

/// A hash in the opposite byte order, which converts between the internal order hashes
/// are computed in and the display order they are printed and parsed in.
pub fn reversed(hash: &[u8; 32]) -> [u8; 32] {
    let mut out = *hash;
    out.reverse();
    out
}

pub fn merkle_root(coinbase_txid: &[u8; 32], branches: &[[u8; 32]]) -> [u8; 32] {
    let mut acc = *coinbase_txid;
    let mut combined = [0u8; 2 * HASH_SIZE];
    for b in branches {
        combined[..HASH_SIZE].copy_from_slice(&acc);
        combined[HASH_SIZE..].copy_from_slice(b);
        acc = sha256d(&combined);
    }
    acc
}

/// The transaction id: the double-SHA256 of the serialization with any witness data
/// stripped, which is version, the input and output body, then lock_time.
pub fn txid(tx: &[u8]) -> Result<[u8; 32], TxError> {
    let mut c = Cursor::new(tx);
    let (version, has_witness) = read_version_and_marker(&mut c)?;

    let body_start = c.pos();
    let inputs = decode_compact_size(&mut c)?;
    if inputs == 0 {
        return Err(TxError::NoInputs);
    }
    for _ in 0..inputs {
        c.advance(OUTPOINT_SIZE, "outpoint")?;
        let len = decode_compact_size(&mut c)? as usize;
        c.advance(len, "scriptSig")?;
        c.advance(SEQUENCE_SIZE, "sequence")?;
    }
    let outputs = decode_compact_size(&mut c)?;
    for _ in 0..outputs {
        c.advance(VALUE_SIZE, "value")?;
        let len = decode_compact_size(&mut c)? as usize;
        c.advance(len, "scriptPubKey")?;
    }
    let body_end = c.pos();

    if has_witness {
        skip_witnesses(&mut c, inputs)?;
    }
    let lock_time = read_lock_time(&mut c, tx.len())?;

    let framing = TX_VERSION_SIZE + LOCK_TIME_SIZE;
    let mut stripped = Vec::with_capacity(framing + (body_end - body_start));
    stripped.extend_from_slice(&version.to_le_bytes());
    stripped.extend_from_slice(&tx[body_start..body_end]);
    stripped.extend_from_slice(&lock_time.to_le_bytes());
    Ok(sha256d(&stripped))
}

/// Reads the version and the optional SegWit marker and flag, reporting whether the
/// transaction carries witness data.
fn read_version_and_marker(c: &mut Cursor<'_>) -> Result<(u32, bool), TxError> {
    let version = c.u32("version")?;
    let has_witness = c.peek2() == Some(SEGWIT_MARKER_AND_FLAG);
    if has_witness {
        c.advance(SEGWIT_MARKER_AND_FLAG_SIZE, "segwit marker and flag")?;
    }
    Ok((version, has_witness))
}

/// Advances past one witness stack per input.
fn skip_witnesses(c: &mut Cursor<'_>, inputs: u64) -> Result<(), TxError> {
    for _ in 0..inputs {
        let items = decode_compact_size(c)?;
        for _ in 0..items {
            let len = decode_compact_size(c)? as usize;
            c.advance(len, "witness item")?;
        }
    }
    Ok(())
}

/// Reads the closing lock_time and requires that it end the transaction.
fn read_lock_time(c: &mut Cursor<'_>, tx_len: usize) -> Result<u32, TxError> {
    let lock_time = c.u32("lock time")?;
    if !c.at_end() {
        return Err(TxError::TrailingBytes(tx_len - c.pos()));
    }
    Ok(lock_time)
}

/// The merkle root of a whole block's transaction ids, and whether the tree is mutated:
/// a level in which a hash is duplicated builds the same root as a shorter list, so a
/// block carrying one is rejected. None for an empty list, which is not a block.
pub fn merkle_root_of(txids: &[[u8; 32]]) -> Option<([u8; 32], bool)> {
    if txids.is_empty() {
        return None;
    }
    let mut level = txids.to_vec();
    let mut combined = [0u8; 2 * HASH_SIZE];
    let mut mutated = false;
    while level.len() > 1 {
        for pair in level.as_chunks::<2>().0 {
            if pair[0] == pair[1] {
                mutated = true;
                break;
            }
        }
        if level.len() % 2 == 1 {
            let last = *level.last().expect("non-empty");
            level.push(last);
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            combined[..HASH_SIZE].copy_from_slice(&pair[0]);
            combined[HASH_SIZE..].copy_from_slice(&pair[1]);
            next.push(sha256d(&combined));
        }
        level = next;
    }
    Some((level[0], mutated))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    pub value: u64,
    pub script: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinbaseTx {
    pub version: u32,
    pub script_sig_offset: usize,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,
    pub has_witness: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TxError {
    #[error("transaction truncated at {0}")]
    Truncated(&'static str),
    #[error("non-canonical CompactSize")]
    BadCompactSize,
    #[error("input count is not 1")]
    NotCoinbase,
    #[error("input does not spend the null outpoint")]
    InputNotNull,
    #[error("{0} implies more bytes than the input holds")]
    LengthOverflow(&'static str),
    #[error("{0} bytes after lock_time")]
    TrailingBytes(usize),
    #[error("input count is zero")]
    NoInputs,
}

impl From<Truncated> for TxError {
    fn from(t: Truncated) -> Self {
        Self::Truncated(t.0)
    }
}

pub fn parse_coinbase(tx: &[u8]) -> Result<CoinbaseTx, TxError> {
    let mut c = Cursor::new(tx);
    let (version, has_witness) = read_version_and_marker(&mut c)?;

    if decode_compact_size(&mut c)? != 1 {
        return Err(TxError::NotCoinbase);
    }
    let prevout = c.take(OUTPOINT_SIZE, "outpoint")?;
    if prevout[..HASH_SIZE] != [0u8; HASH_SIZE] || prevout[HASH_SIZE..] != NULL_OUTPOINT_INDEX {
        return Err(TxError::InputNotNull);
    }
    let script_len = decode_compact_size(&mut c)? as usize;
    let script_sig_offset = c.pos();
    let script_sig = c.take(script_len, "scriptSig")?.to_vec();
    let sequence = c.u32("sequence")?;

    let n_out = decode_compact_size(&mut c)? as usize;
    if n_out.saturating_mul(MIN_OUTPUT_SIZE) > c.rest().len() {
        return Err(TxError::LengthOverflow("output count"));
    }
    let mut outputs = Vec::with_capacity(n_out);
    for _ in 0..n_out {
        let value = c.u64("value")?;
        let len = decode_compact_size(&mut c)? as usize;
        let script = c.take(len, "scriptPubKey")?.to_vec();
        outputs.push(TxOut { value, script });
    }

    if has_witness {
        skip_witnesses(&mut c, 1)?;
    }
    let lock_time = read_lock_time(&mut c, tx.len())?;

    Ok(CoinbaseTx {
        version,
        script_sig_offset,
        script_sig,
        sequence,
        outputs,
        lock_time,
        has_witness,
    })
}

/// One step of a script: the opcode, and for a push the offset its data starts at and
/// the data itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScriptOp<'a> {
    pub opcode: u8,
    pub push: Option<(usize, &'a [u8])>,
}

/// Walks `script` one opcode at a time. Scanning stops at the first push whose length
/// field or data runs past the end of the script, which is where Bitcoin Core's own
/// script walk stops.
pub fn script_ops(script: &[u8]) -> impl Iterator<Item = ScriptOp<'_>> {
    ScriptOps { script, at: 0 }
}

struct ScriptOps<'a> {
    script: &'a [u8],
    at: usize,
}

impl<'a> Iterator for ScriptOps<'a> {
    type Item = ScriptOp<'a>;

    fn next(&mut self) -> Option<ScriptOp<'a>> {
        let opcode = *self.script.get(self.at)?;
        let length_bytes = match opcode {
            0x01..=opcode::MAX_DIRECT_PUSH_OPCODE => 0,
            opcode::OP_PUSHDATA1 => 1,
            opcode::OP_PUSHDATA2 => 2,
            opcode::OP_PUSHDATA4 => 4,
            _ => {
                self.at += 1;
                return Some(ScriptOp { opcode, push: None });
            }
        };
        let after_opcode = self.at + 1;
        let (data_at, len) = if length_bytes == 0 {
            (after_opcode, usize::from(opcode))
        } else {
            let field = self.script.get(after_opcode..after_opcode + length_bytes)?;
            let len = field.iter().rev().fold(0usize, |n, b| (n << 8) | usize::from(*b));
            (after_opcode + length_bytes, len)
        };
        let end = data_at.checked_add(len)?;
        let data = self.script.get(data_at..end)?;
        self.at = end;
        Some(ScriptOp { opcode, push: Some((data_at, data)) })
    }
}

/// Every data push in `script`, as the offset its data starts at and the data itself.
pub fn script_pushes(script: &[u8]) -> Vec<(usize, &[u8])> {
    script_ops(script).filter_map(|op| op.push).collect()
}

pub fn output_script_size_is_valid(script: &[u8]) -> bool {
    if script.is_empty() {
        return true;
    }
    let limit = if script[0] == OP_RETURN { MAX_OUTPUT_DATA_SIZE } else { MAX_OUTPUT_SCRIPT_SIZE };
    script.len() <= limit
}

const COMPACT_SIZE_U16_TAG: u8 = 0xfd;
const COMPACT_SIZE_U32_TAG: u8 = 0xfe;
const COMPACT_SIZE_U64_TAG: u8 = 0xff;
const COMPACT_SIZE_MAX_1: u64 = COMPACT_SIZE_U16_TAG as u64 - 1;
const COMPACT_SIZE_MAX_2: u64 = u16::MAX as u64;
const COMPACT_SIZE_MAX_4: u64 = u32::MAX as u64;

fn decode_compact_size(c: &mut Cursor<'_>) -> Result<u64, TxError> {
    let first = c.u8("compact size")?;
    let (v, minimum) = match first {
        COMPACT_SIZE_U16_TAG => (u64::from(c.u16("compact size")?), COMPACT_SIZE_MAX_1 + 1),
        COMPACT_SIZE_U32_TAG => (u64::from(c.u32("compact size")?), COMPACT_SIZE_MAX_2 + 1),
        COMPACT_SIZE_U64_TAG => (c.u64("compact size")?, COMPACT_SIZE_MAX_4 + 1),
        n => (u64::from(n), 0),
    };
    if v < minimum {
        return Err(TxError::BadCompactSize);
    }
    Ok(v)
}

pub fn encode_compact_size(n: u64) -> Vec<u8> {
    match n {
        0..=COMPACT_SIZE_MAX_1 => vec![n as u8],
        _ if n <= COMPACT_SIZE_MAX_2 => {
            let mut v = vec![COMPACT_SIZE_U16_TAG];
            v.extend_from_slice(&(n as u16).to_le_bytes());
            v
        }
        _ if n <= COMPACT_SIZE_MAX_4 => {
            let mut v = vec![COMPACT_SIZE_U32_TAG];
            v.extend_from_slice(&(n as u32).to_le_bytes());
            v
        }
        _ => {
            let mut v = vec![COMPACT_SIZE_U64_TAG];
            v.extend_from_slice(&n.to_le_bytes());
            v
        }
    }
}

pub fn encode_push(data: &[u8]) -> Vec<u8> {
    debug_assert!(u8::try_from(data.len()).is_ok());
    let mut out = if data.len() <= opcode::MAX_DIRECT_PUSH {
        vec![data.len() as u8]
    } else {
        vec![opcode::OP_PUSHDATA1, data.len() as u8]
    };
    out.extend_from_slice(data);
    out
}

pub fn encode_output(value: u64, script: &[u8]) -> Vec<u8> {
    let mut v = value.to_le_bytes().to_vec();
    v.extend_from_slice(&encode_compact_size(script.len() as u64));
    v.extend_from_slice(script);
    v
}

pub fn serialize_block(header: &[u8], coinbase: &[u8], other_txns: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(header.len() + coinbase.len() + MAX_COMPACT_SIZE_LEN);
    out.extend_from_slice(header);
    out.extend_from_slice(&encode_compact_size(other_txns.len() as u64 + 1));
    out.extend_from_slice(coinbase);
    for tx in other_txns {
        out.extend_from_slice(tx);
    }
    out
}
