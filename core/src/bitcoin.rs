use crate::cursor::{Cursor, Truncated};
use bytes::BufMut as _;
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

pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    Sha256::digest(first).into()
}

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
    stripped.put_u32_le(version);
    stripped.put_slice(&tx[body_start..body_end]);
    stripped.put_u32_le(lock_time);
    Ok(sha256d(&stripped))
}

fn read_version_and_marker(c: &mut Cursor<'_>) -> Result<(u32, bool), TxError> {
    let version = c.u32("version")?;
    let has_witness = c.peek2() == Some(SEGWIT_MARKER_AND_FLAG);
    if has_witness {
        c.advance(SEGWIT_MARKER_AND_FLAG_SIZE, "segwit marker and flag")?;
    }
    Ok((version, has_witness))
}

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

fn read_lock_time(c: &mut Cursor<'_>, tx_len: usize) -> Result<u32, TxError> {
    let lock_time = c.u32("lock time")?;
    if !c.at_end() {
        return Err(TxError::TrailingBytes(tx_len - c.pos()));
    }
    Ok(lock_time)
}

pub fn merkle_root_of(txids: &[[u8; 32]]) -> Option<([u8; 32], bool)> {
    if txids.is_empty() {
        return None;
    }
    let mut level = txids.to_vec();
    let mut combined = [0u8; 2 * HASH_SIZE];
    let mut mutated = false;
    while level.len() > 1 {
        mutated |= level.as_chunks::<2>().0.iter().any(|[a, b]| a == b);
        if level.len() % 2 == 1 {
            let last = *level.last().expect("non-empty");
            level.push(last);
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for [a, b] in level.as_chunks::<2>().0 {
            combined[..HASH_SIZE].copy_from_slice(a);
            combined[HASH_SIZE..].copy_from_slice(b);
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScriptOp<'a> {
    pub opcode: u8,
    pub push: Option<(usize, &'a [u8])>,
}

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

pub fn script_pushes(script: &[u8]) -> Vec<(usize, &[u8])> {
    script_ops(script).filter_map(|op| op.push).collect()
}

pub fn output_script_size_is_valid(script: &[u8]) -> bool {
    if script.is_empty() {
        return true;
    }
    let limit =
        if script[0] == opcode::OP_RETURN { MAX_OUTPUT_DATA_SIZE } else { MAX_OUTPUT_SCRIPT_SIZE };
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
    let mut v = Vec::with_capacity(MAX_COMPACT_SIZE_LEN);
    match n {
        0..=COMPACT_SIZE_MAX_1 => v.put_u8(n as u8),
        _ if n <= COMPACT_SIZE_MAX_2 => {
            v.put_u8(COMPACT_SIZE_U16_TAG);
            v.put_u16_le(n as u16);
        }
        _ if n <= COMPACT_SIZE_MAX_4 => {
            v.put_u8(COMPACT_SIZE_U32_TAG);
            v.put_u32_le(n as u32);
        }
        _ => {
            v.put_u8(COMPACT_SIZE_U64_TAG);
            v.put_u64_le(n);
        }
    }
    v
}

pub fn encode_push(data: &[u8]) -> Vec<u8> {
    debug_assert!(u8::try_from(data.len()).is_ok());
    let mut out = Vec::with_capacity(2 + data.len());
    if data.len() > opcode::MAX_DIRECT_PUSH {
        out.put_u8(opcode::OP_PUSHDATA1);
    }
    out.put_u8(data.len() as u8);
    out.put_slice(data);
    out
}

pub fn encode_output(value: u64, script: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(VALUE_SIZE + MAX_COMPACT_SIZE_LEN + script.len());
    v.put_u64_le(value);
    v.put_slice(&encode_compact_size(script.len() as u64));
    v.put_slice(script);
    v
}

pub fn serialize_block(header: &[u8], coinbase: &[u8], other_txns: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(header.len() + coinbase.len() + MAX_COMPACT_SIZE_LEN);
    out.put_slice(header);
    out.put_slice(&encode_compact_size(other_txns.len() as u64 + 1));
    out.put_slice(coinbase);
    for tx in other_txns {
        out.put_slice(tx);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{encode_compact_size, encode_output, encode_push, serialize_block};

    #[test]
    fn pushes_and_outputs() {
        assert_eq!(encode_push(&[1, 2]), vec![2, 1, 2]);
        let long = [7u8; 80];
        let p = encode_push(&long);
        assert_eq!(&p[..2], &[0x4c, 80]);
        assert_eq!(p.len(), 82);
        let o = encode_output(1, &[0x6a]);
        assert_eq!(o, vec![1, 0, 0, 0, 0, 0, 0, 0, 1, 0x6a]);
    }

    #[test]
    fn compact_size_boundaries() {
        assert_eq!(encode_compact_size(0), vec![0x00]);
        assert_eq!(encode_compact_size(0xfc), vec![0xfc]);
        assert_eq!(encode_compact_size(0xfd), vec![0xfd, 0xfd, 0x00]);
        assert_eq!(encode_compact_size(0xffff), vec![0xfd, 0xff, 0xff]);
        assert_eq!(encode_compact_size(0x1_0000), vec![0xfe, 0x00, 0x00, 0x01, 0x00]);
        assert_eq!(encode_compact_size(0x1_0000_0000), vec![0xff, 0, 0, 0, 0, 1, 0, 0, 0]);
    }

    #[test]
    fn serializes_a_coinbase_only_block() {
        let header = [0xaa; 164];
        let coinbase = vec![0xbb; 100];
        let block = serialize_block(&header, &coinbase, &[]);
        assert_eq!(block.len(), 164 + 1 + 100);
        assert_eq!(&block[..164], &header);
        assert_eq!(block[164], 1);
        assert_eq!(&block[165..], &coinbase[..]);
    }

    #[test]
    fn serializes_a_block_with_template_transactions() {
        let block = serialize_block(&[0xaa; 164], &[0xbb; 10], &[vec![0xcc; 4], vec![0xdd; 6]]);
        assert_eq!(block.len(), 164 + 1 + 10 + 4 + 6);
        assert_eq!(block[164], 3);
        assert_eq!(&block[175..179], &[0xcc; 4]);
        assert_eq!(&block[179..], &[0xdd; 6]);
    }

    #[test]
    fn serializes_a_block_with_a_multibyte_transaction_count() {
        let header = [0xaa; 164];
        let coinbase = vec![0xbb; 30];
        let others: Vec<Vec<u8>> = (0..300).map(|i| vec![i as u8; 4]).collect();
        let block = serialize_block(&header, &coinbase, &others);
        assert_eq!(&block[..164], &header);
        assert_eq!(&block[164..167], &[0xfd, 0x2d, 0x01], "301 transactions as a CompactSize");
        assert_eq!(&block[167..197], &coinbase[..]);
        assert_eq!(block.len(), 164 + 3 + 30 + 300 * 4);
    }

    #[test]
    fn txids_and_merkle_root_of_a_real_segwit_block() {
        const CB: &str = "020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016600ffffffff02980e062a01000000160014bab23ecf21b310bc7d0d15586cb2f664549891e30000000000000000266a24aa21a9eddfbb7ab1c43280e437fcb6033e7f5f24c9b5b2b3f0dccb53c880c9b6c31947060120000000000000000000000000000000000000000000000000000000000000000000000000";
        const SEGWIT_SPEND: &str = "02000000000101f3484e7f822714020226e36f0e18bf6d962241c1f1f34cdbabbe31c82c4ecea80000000000fdffffff0200e1f50500000000160014bab23ecf21b310bc7d0d15586cb2f664549891e3c0051024010000001976a914f8ae76700eda2583872feb722b1d162481f0e63888ac0247304402207a281602d2717d6c3da0139626ffce6f81a8dccf29ad57a21f9f65e40c8f0bfb02205dd3f89c4818bfa5892c3bff0a045390e2b49c114fad5c820759b1adfb649a3101210294a4f2a020d573502fd3da5a1afbc3e54a76dd44cb9ceaa477403b68040d3a6f65000000";
        const PLAIN_SPEND: &str = "020000000198d551118f5477913961477eceff0080fc9677244f8479c61cc91d7a259af956010000006a47304402201172837cc61e1a803f75e63dfe5436d851fec6ae734caab113bd63e26993a84f022034e411c166c5943d563573f9984a3ed5576b773cd49c3aa12733c17103ff23b8012102c8a978823ce4856d4f0c6fe6e17fe7f957f8036002e7c59eeaf8c49666fccd93fdffffff0268322418010000001976a91461bb598c6a0a8fbce3bea6d93844ae7424f9f13d88ac00c2eb0b00000000160014bab23ecf21b310bc7d0d15586cb2f664549891e365000000";
        const TXIDS: [&str; 3] = [
            "d995e08728cb0976283c0af6aec720e33b61e2686dedd45a481ceb3a7b69608c",
            "56f99a257a1dc91cc679844f247796fc8000ffce7e4761399177548f1151d598",
            "07f0c0149d5f5b7936a85dd996089f8fb5624eb6923d419976ad9f88ef9b5fa1",
        ];
        const MERKLE_ROOT: &str =
            "e2c77a724dd77d59e5853561b562451f41f823dcaa6c0f3f417963882bce9a1a";

        let raws = [CB, SEGWIT_SPEND, PLAIN_SPEND];
        let mut ids = Vec::new();
        for (raw, want) in raws.iter().zip(TXIDS) {
            let bytes = hex::decode(raw).unwrap();
            let id = super::txid(&bytes).unwrap();
            assert_eq!(hex::encode(super::reversed(&id)), want, "txid of {want}");
            ids.push(id);
        }
        assert_ne!(super::sha256d(&hex::decode(CB).unwrap()), ids[0]);
        assert_ne!(super::sha256d(&hex::decode(SEGWIT_SPEND).unwrap()), ids[1]);
        assert_eq!(super::sha256d(&hex::decode(PLAIN_SPEND).unwrap()), ids[2]);

        let (root, mutated) = super::merkle_root_of(&ids).unwrap();
        assert_eq!(hex::encode(super::reversed(&root)), MERKLE_ROOT);
        assert!(!mutated);
    }

    #[test]
    fn merkle_root_of_one_transaction_is_that_transaction() {
        let only = [7u8; 32];
        assert_eq!(super::merkle_root_of(&[only]), Some((only, false)));
        assert_eq!(super::merkle_root_of(&[]), None);
    }

    #[test]
    fn a_duplicated_leaf_pair_is_flagged_as_mutated() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        let (original_root, original_mutated) = super::merkle_root_of(&[a, b, c]).unwrap();
        assert!(!original_mutated, "the three-leaf list is not a mutation");

        let (duplicated_root, duplicated_mutated) = super::merkle_root_of(&[a, b, c, c]).unwrap();
        assert_eq!(duplicated_root, original_root, "the duplicated list produces the same root");
        assert!(duplicated_mutated, "the duplicated adjacent pair is reported as mutated");
    }

    #[test]
    fn trailing_bytes_after_lock_time_are_refused() {
        let raw = hex::decode(GENESIS_CB).unwrap();
        assert!(super::parse_coinbase(&raw).is_ok());
        let mut extended = raw.clone();
        extended.push(0x00);
        assert!(matches!(super::parse_coinbase(&extended), Err(super::TxError::TrailingBytes(1))));
    }

    use super::*;

    const GENESIS_CB: &str = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";

    #[test]
    fn sha256d_matches_the_genesis_merkle_root() {
        let tx = hex::decode(GENESIS_CB).unwrap();
        let h = sha256d(&tx);
        assert_eq!(
            hex::encode(reversed(&h)),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
        );
    }

    #[test]
    fn merkle_root_with_no_branches_is_the_coinbase_txid() {
        let cb = [0x37u8; 32];
        assert_eq!(merkle_root(&cb, &[]), cb);
    }

    #[test]
    fn merkle_root_hashes_the_accumulator_on_the_left() {
        let cb = [0x01u8; 32];
        let b0 = [0x02u8; 32];
        let b1 = [0x03u8; 32];
        let mut step = [0u8; 64];
        step[..32].copy_from_slice(&cb);
        step[32..].copy_from_slice(&b0);
        let one = sha256d(&step);
        step[..32].copy_from_slice(&one);
        step[32..].copy_from_slice(&b1);
        assert_eq!(merkle_root(&cb, &[b0, b1]), sha256d(&step));
        step[..32].copy_from_slice(&b0);
        step[32..].copy_from_slice(&cb);
        assert_ne!(merkle_root(&cb, &[b0]), sha256d(&step));
    }

    #[test]
    fn parses_the_genesis_coinbase() {
        let tx = hex::decode(GENESIS_CB).unwrap();
        let cb = parse_coinbase(&tx).unwrap();
        assert_eq!(cb.version, 1);
        assert!(!cb.has_witness);
        assert_eq!(cb.script_sig.len(), 0x4d);
        assert_eq!(&tx[cb.script_sig_offset..cb.script_sig_offset + 4], &cb.script_sig[..4]);
        assert_eq!(cb.sequence, 0xffff_ffff);
        assert_eq!(cb.outputs.len(), 1);
        assert_eq!(cb.outputs[0].value, 50_0000_0000);
        assert_eq!(cb.outputs[0].script.len(), 67);
        assert_eq!(cb.lock_time, 0);
        assert_eq!(cb.outputs.iter().map(|o| o.value).sum::<u64>(), 50_0000_0000);
    }

    #[test]
    fn parses_a_segwit_coinbase() {
        let tx = hex::decode(
            "020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0151ffffffff0200f2052a010000000151000000000000000026\
             6a24aa21a9ed0000000000000000000000000000000000000000000000000000000000000000\
             0120000000000000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        let cb = parse_coinbase(&tx).unwrap();
        assert!(cb.has_witness);
        assert_eq!(cb.script_sig, vec![0x51]);
        assert_eq!(cb.outputs.len(), 2);
        assert_eq!(cb.outputs[1].value, 0);
        assert_eq!(cb.outputs[1].script[0], 0x6a);
        assert_eq!(cb.lock_time, 0);
    }

    #[test]
    fn rejects_malformed_transactions() {
        let tx = hex::decode(GENESIS_CB).unwrap();
        assert!(matches!(parse_coinbase(&tx[..20]), Err(TxError::Truncated(_))));

        let mut two = tx.clone();
        two[4] = 2;
        assert_eq!(parse_coinbase(&two), Err(TxError::NotCoinbase));

        let mut spend = tx.clone();
        spend[5] = 0x01;
        assert_eq!(parse_coinbase(&spend), Err(TxError::InputNotNull));

        let mut long = tx.clone();
        long[41] = 0xfe;
        assert!(parse_coinbase(&long).is_err());
    }

    #[test]
    fn rejects_non_minimal_compact_sizes() {
        let tx = hex::decode("01000000fd0100").unwrap();
        assert_eq!(parse_coinbase(&tx), Err(TxError::BadCompactSize));
    }

    #[test]
    fn output_script_sizes_follow_the_consensus_rule() {
        assert!(output_script_size_is_valid(&[0xab; 34]));
        assert!(!output_script_size_is_valid(&[0xab; 35]));

        let mut data = vec![opcode::OP_RETURN];
        data.extend_from_slice(&[0xcd; 82]);
        assert_eq!(data.len(), 83);
        assert!(output_script_size_is_valid(&data));
        data.push(0xcd);
        assert!(!output_script_size_is_valid(&data));

        assert!(output_script_size_is_valid(&[]));
    }

    #[test]
    fn every_address_type_fits_but_a_future_witness_program_need_not() {
        for len in [22usize, 23, 25, 34] {
            assert!(output_script_size_is_valid(&vec![0x00; len]), "{len} bytes");
        }

        let mut witness_unknown = vec![0x52, 40];
        witness_unknown.extend_from_slice(&[0xef; 40]);
        assert_eq!(witness_unknown.len(), 42);
        assert!(witness_unknown.len() <= crate::datum::messages::MAX_OUTPUT_SCRIPT);
        assert!(!output_script_size_is_valid(&witness_unknown));
    }

    #[test]
    fn reads_script_pushes() {
        let script = [0x03, b'a', b'b', b'c', 0x4c, 0x02, b'd', b'e', 0x6a, 0xff];
        let pushes = script_pushes(&script);
        assert_eq!(pushes.len(), 2);
        assert_eq!(pushes[0], (1, &b"abc"[..]));
        assert_eq!(pushes[1], (6, &b"de"[..]));

        assert!(script_pushes(&[0x05, 0x01, 0x02]).is_empty());
    }

    #[test]
    fn skips_non_pushdata_opcodes_such_as_a_low_bip34_height() {
        let script = [0x56, 0x03, b'a', b'b', b'c', 0x02, b'd', b'e'];
        let pushes = script_pushes(&script);
        assert_eq!(pushes.len(), 2);
        assert_eq!(pushes[0], (2, &b"abc"[..]));
        assert_eq!(pushes[1], (6, &b"de"[..]));

        let with_gap = [0x56, 0x01, b'x', 0x51, 0x01, b'y'];
        assert_eq!(script_pushes(&with_gap), vec![(2, &b"x"[..]), (5, &b"y"[..])]);
    }
}
