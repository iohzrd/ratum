//! Fixtures the crate's unit tests and the integration harness share: the coinbase a
//! gateway would build, in the tagging layout the pool's `ratum_prime::verify` checks. The unit tests and
//! the integration tests must use that layout byte for byte, so it is written once here
//! rather than once per test tree. The pool binary does not use this module.

use crate::bitcoin::opcode::{OP_0, OP_RETURN};
use crate::bitcoin::{
    HASH_SIZE, LOCK_TIME_SIZE, NULL_OUTPOINT_INDEX, SEQUENCE_FINAL, WITNESS_COMMITMENT_HEADER,
    encode_compact_size, encode_output, encode_push,
};
use crate::datum::coinbase::{ENPREFIX_SIZE, UID_PUSH_POT_AT, tag_push_data, uid_push};
use crate::datum::messages::CoinbaseOutput;
use crate::datum::share::{self, CoinbaseSection};

/// A P2WPKH program: 20 bytes, the length HASH160 produces.
const HASH160_SIZE: usize = 20;

pub fn p2wpkh(b: u8) -> Vec<u8> {
    let mut s = vec![OP_0, HASH160_SIZE as u8];
    s.extend_from_slice(&[b; HASH160_SIZE]);
    s
}

/// How the coinbase identifies the pool: the tag push the pool searches for, then the
/// `UID_PUSH_SIZE_V1` push whose last four bytes are its prime id. The PoT (power-of-two
/// difficulty) byte is the first byte of that push.
pub struct Tagging<'a> {
    pub tag: &'a str,
    /// The gateway operator's own tag, written after the pool's tag and a 0x0f marker;
    /// empty writes no marker. The layout is `coinbase::script_sig` in the gateway crate.
    pub tag_secondary: &'a str,
    pub prime_id: u32,
}

/// The block height the fixture coinbase claims, written as a BIP34 push. Above 16 and
/// under 2^23, so it encodes as a plain three-byte little-endian push.
const FIXTURE_HEIGHT: u32 = 2_544_140;
/// The fixture's `coinbase_unique_id`; the gateway's own default is 4242.
const FIXTURE_UNIQUE_ID: u16 = 0x1234;
/// The fixture's extranonce prefix, which stands where a job's counter would.
const FIXTURE_ENPREFIX: [u8; ENPREFIX_SIZE] = [0xab, 0xcd];
/// The generation transaction's `nVersion`.
const COINBASE_TX_VERSION: u32 = 1;
/// The outputs the fixture adds after the dictated ones: the pool's payout and the witness
/// commitment.
const FIXED_OUTPUTS: usize = 2;

/// A coinbase split in two around the extranonce: it pays `outputs`, then the remainder
/// to `payout_script`, then a zero-value witness commitment. Returns the section and the
/// index of the PoT byte in the assembled transaction.
pub fn coinbase(
    tagging: &Tagging<'_>,
    payout_script: &[u8],
    outputs: &[CoinbaseOutput],
    coinbase_value: u64,
) -> (CoinbaseSection, usize) {
    // The BIP34 height push: the low three bytes of the height, little-endian.
    let mut script = encode_push(&FIXTURE_HEIGHT.to_le_bytes()[..3]);
    let tag = tag_push_data(tagging.tag.as_bytes(), tagging.tag_secondary.as_bytes());
    script.extend_from_slice(&encode_push(&tag));
    let pot_in_script = script.len() + UID_PUSH_POT_AT;
    script.extend_from_slice(&uid_push(FIXTURE_UNIQUE_ID, &tagging.prime_id.to_le_bytes()));
    // The extranonce push: the enprefix, then the 12-byte extranonce the assembler inserts.
    script.push((ENPREFIX_SIZE + share::EXTRANONCE_SIZE) as u8);
    script.extend_from_slice(&FIXTURE_ENPREFIX);

    // The version, then one input spending the null outpoint.
    let mut coinb1 = COINBASE_TX_VERSION.to_le_bytes().to_vec();
    coinb1.extend_from_slice(&encode_compact_size(1));
    coinb1.extend_from_slice(&[0u8; HASH_SIZE]);
    coinb1.extend_from_slice(&NULL_OUTPOINT_INDEX);
    coinb1.extend_from_slice(&encode_compact_size((script.len() + share::EXTRANONCE_SIZE) as u64));
    let script_sig_offset = coinb1.len();
    coinb1.extend_from_slice(&script);
    let pot_index = script_sig_offset + pot_in_script;

    let mut coinb2 = SEQUENCE_FINAL.to_vec();
    let paid: u64 = outputs.iter().map(|o| o.value).sum();
    coinb2.extend_from_slice(&encode_compact_size((outputs.len() + FIXED_OUTPUTS) as u64));
    for o in outputs {
        coinb2.extend_from_slice(&encode_output(o.value, &o.script));
    }
    coinb2.extend_from_slice(&encode_output(coinbase_value - paid, payout_script));
    let mut commitment_data = WITNESS_COMMITMENT_HEADER.to_vec();
    commitment_data.extend_from_slice(&[0u8; HASH_SIZE]);
    let mut commitment = vec![OP_RETURN];
    commitment.extend_from_slice(&encode_push(&commitment_data));
    coinb2.extend_from_slice(&encode_output(0, &commitment));
    coinb2.extend_from_slice(&[0u8; LOCK_TIME_SIZE]);

    (CoinbaseSection { coinbase_id: 0, coinb1, coinb2 }, pot_index)
}
