//! Transaction decoding: `txid` over the stripped serialization, since the witness is excluded from
//! the merkle tree, `parse_coinbase` for the transaction the pool rebuilds a share from, and output
//! encoding.

use super::{HASH_SIZE, MAX_COMPACT_SIZE_LEN, decode_compact_size, encode_compact_size, sha256d};
use crate::reader::{ByteReader, Truncated};
use bytes::BufMut as _;

pub(crate) const TX_VERSION_SIZE: usize = 4;
pub(crate) const OUTPOINT_SIZE: usize = HASH_SIZE + 4;
pub(crate) const SEQUENCE_SIZE: usize = 4;
pub(crate) const VALUE_SIZE: usize = 8;
pub(crate) const LOCK_TIME_SIZE: usize = 4;
pub(crate) const MIN_OUTPUT_SIZE: usize = VALUE_SIZE + 1;
const SEGWIT_MARKER_AND_FLAG: (u8, u8) = (0x00, 0x01);
const SEGWIT_MARKER_AND_FLAG_SIZE: usize = 2;

pub(crate) const NULL_OUTPOINT_INDEX: [u8; OUTPOINT_SIZE - HASH_SIZE] =
    [0xff; OUTPOINT_SIZE - HASH_SIZE];
pub(crate) const SEQUENCE_FINAL: [u8; SEQUENCE_SIZE] = [0xff; SEQUENCE_SIZE];

pub fn txid(tx: &[u8]) -> Result<[u8; 32], TxError> {
    let mut c = ByteReader::new(tx);
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

fn read_version_and_marker(c: &mut ByteReader<'_>) -> Result<(u32, bool), TxError> {
    let version = c.u32("version")?;
    let has_witness = c.peek2() == Some(SEGWIT_MARKER_AND_FLAG);
    if has_witness {
        c.advance(SEGWIT_MARKER_AND_FLAG_SIZE, "segwit marker and flag")?;
    }
    Ok((version, has_witness))
}

fn skip_witnesses(c: &mut ByteReader<'_>, inputs: u64) -> Result<(), TxError> {
    for _ in 0..inputs {
        let items = decode_compact_size(c)?;
        for _ in 0..items {
            let len = decode_compact_size(c)? as usize;
            c.advance(len, "witness item")?;
        }
    }
    Ok(())
}

fn read_lock_time(c: &mut ByteReader<'_>, tx_len: usize) -> Result<u32, TxError> {
    let lock_time = c.u32("lock time")?;
    if !c.at_end() {
        return Err(TxError::TrailingBytes(tx_len - c.pos()));
    }
    Ok(lock_time)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
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
    Truncated(#[from] Truncated),
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

pub fn parse_coinbase(tx: &[u8]) -> Result<CoinbaseTx, TxError> {
    let mut c = ByteReader::new(tx);
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
        outputs.push(TxOut { value, script_pubkey: script });
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

pub(crate) fn encode_output(value: u64, script: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(VALUE_SIZE + MAX_COMPACT_SIZE_LEN + script.len());
    v.put_u64_le(value);
    v.put_slice(&encode_compact_size(script.len() as u64));
    v.put_slice(script);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::{merkle_tree_root, reversed};

    const GENESIS_CB: &str = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";

    #[test]
    fn encodes_an_output() {
        let o = encode_output(1, &[0x6a]);
        assert_eq!(o, vec![1, 0, 0, 0, 0, 0, 0, 0, 1, 0x6a]);
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
            let id = txid(&bytes).unwrap();
            assert_eq!(hex::encode(reversed(&id)), want, "txid of {want}");
            ids.push(id);
        }
        assert_ne!(sha256d(&hex::decode(CB).unwrap()), ids[0]);
        assert_ne!(sha256d(&hex::decode(SEGWIT_SPEND).unwrap()), ids[1]);
        assert_eq!(sha256d(&hex::decode(PLAIN_SPEND).unwrap()), ids[2]);

        let tree = merkle_tree_root(&ids).unwrap();
        assert_eq!(hex::encode(reversed(&tree.root)), MERKLE_ROOT);
        assert!(!tree.mutated);
    }

    #[test]
    fn trailing_bytes_after_lock_time_are_refused() {
        let raw = hex::decode(GENESIS_CB).unwrap();
        assert!(parse_coinbase(&raw).is_ok());
        let mut extended = raw.clone();
        extended.push(0x00);
        assert!(matches!(parse_coinbase(&extended), Err(TxError::TrailingBytes(1))));
    }

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
        assert_eq!(cb.outputs[0].script_pubkey.len(), 67);
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
        assert_eq!(cb.outputs[1].script_pubkey[0], 0x6a);
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
}
