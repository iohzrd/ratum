//! Test values both binaries' tests build on: hashes, output scripts, and a coinbase assembled the
//! way the gateway assembles one. Compiled under `cfg(test)` and behind the `test-support` feature.

use crate::bitcoin::transaction::TxOut;
use crate::datum::coinbase::{
    BlockLimits, BuiltCoinbase, CoinbaseSpec, ScriptSigInputs, build, script_sig,
};

pub fn hash(n: u64) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&n.to_be_bytes());
    h
}

pub fn ramp(start: u8) -> [u8; 32] {
    std::array::from_fn(|i| start.wrapping_add(i as u8))
}

pub fn p2wpkh(b: u8) -> Vec<u8> {
    let mut s = vec![0x00, 0x14];
    s.extend_from_slice(&[b; 20]);
    s
}

pub fn p2pkh(b: u8) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 0x14];
    s.extend_from_slice(&[b; 20]);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

pub struct ScriptSigTags<'a> {
    pub tag_primary: &'a str,
    pub tag_secondary: &'a str,
    pub prime_id: u32,
}

const HEIGHT: u32 = 2_544_140;
const UNIQUE_ID: u16 = 0x1234;
const ENPREFIX: u16 = 0xabcd;
const WITNESS_COMMITMENT_HEADER: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

/// A coinbase built the way the gateway builds one, with every output included and a
/// zero witness commitment.
pub fn coinbase(
    tagging: &ScriptSigTags<'_>,
    payout_script: &[u8],
    outputs: &[TxOut],
    coinbase_value: u64,
) -> BuiltCoinbase {
    let (script, target_byte_index_in_script) = script_sig(&ScriptSigInputs {
        height: HEIGHT,
        tag_primary: tagging.tag_primary,
        tag_secondary: tagging.tag_secondary,
        unique_id: UNIQUE_ID,
        prime_id: u64::from(tagging.prime_id),
        wide_prime: false,
        datum_active: true,
    })
    .expect("the fixture tags fit");
    let mut commitment = WITNESS_COMMITMENT_HEADER.to_vec();
    commitment.extend_from_slice(&[0x00; 32]);
    let (built, _) = build(&CoinbaseSpec {
        coinbase_id: 0,
        script_sig: &script,
        target_byte_index_in_script,
        enprefix: ENPREFIX,
        witness_commitment: Some(&commitment),
        pool_payout_script: payout_script,
        coinbase_value,
        outputs,
        limits: BlockLimits::UNLIMITED,
        sigop_budget: u64::MAX,
    });
    built
}
