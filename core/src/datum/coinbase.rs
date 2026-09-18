//! The coinbase the gateway builds and the pool reads back: the scriptSig carrying the height, the
//! tags and the unique id with the pool's prime id, where the extranonce is spliced in, and how
//! many dictated outputs the block's remaining size and sigops leave room for.

use crate::bitcoin::script::opcode::{
    OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY, OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_RETURN,
};
use crate::bitcoin::script::{encode_push, height_push, script_ops, script_pushes};
use crate::bitcoin::transaction::{
    CoinbaseTx, LOCK_TIME_SIZE, MIN_OUTPUT_SIZE, NULL_OUTPOINT_INDEX, SEQUENCE_FINAL, TxOut,
    encode_output,
};
use crate::bitcoin::{HASH_SIZE, WITNESS_SCALE_FACTOR, encode_compact_size};
use crate::datum::messages::share::{CoinbaseSection, EXTRANONCE_SIZE, MAX_COINBASE_SECTION_LEN};
use bytes::BufMut as _;

pub const TARGET_BYTE_PLACEHOLDER: u8 = 0xFF;

pub(crate) const TAG_SEPARATOR: u8 = 0x0F;
pub(crate) const TAG_END: u8 = 0x00;

pub(crate) const UNIQUE_ID_PUSH_DATA_SIZE_NO_PRIME: usize = 1 + 2;
pub(crate) const UNIQUE_ID_PUSH_DATA_SIZE_V1: usize =
    UNIQUE_ID_PUSH_DATA_SIZE_NO_PRIME + size_of::<u32>();
pub(crate) const UNIQUE_ID_PUSH_DATA_SIZE_V3: usize =
    UNIQUE_ID_PUSH_DATA_SIZE_NO_PRIME + size_of::<u64>();

pub(crate) const ENPREFIX_SIZE: usize = 2;
pub(crate) const EXTRANONCE_PUSH_SIZE: usize = 1 + ENPREFIX_SIZE + EXTRANONCE_SIZE;
pub(crate) const EXTRANONCE_PUSH_OPCODE: u8 = (EXTRANONCE_PUSH_SIZE - 1) as u8;
pub(crate) const TAG_MARKER_BYTES: usize = 2;

pub(crate) const MAX_COINBASE_SCRIPT_SIG_LEN: usize = 100;
pub(crate) const MAX_COINBASE_TAG_SPACE: usize = 86;
pub(crate) const WIDE_PRIME_PUSH_EXTRA_BYTES: usize = 4;

pub(crate) const SCRIPT_SIG_ROOM_FOR_EXTRANONCE: usize =
    MAX_COINBASE_SCRIPT_SIG_LEN - EXTRANONCE_PUSH_SIZE;

const OP_RETURN_EXTRANONCE_OUTPUT_SIZE: usize = MIN_OUTPUT_SIZE + 1 + EXTRANONCE_PUSH_SIZE;

const COINBASE_TX_VERSION: u32 = 1;
const PRUNABLE_OP_RETURN: [u8; 3] = [OP_RETURN, 0x01, 0x00];
const MIN_USEFUL_OUTPUT_ROOM: usize = 30;
const MAX_TXN_COUNT_SIZE: usize = 5;
const COINBASE_WITNESS_BYTES: u64 = 36;

/// The bytes of the scriptSig the tag push may occupy: a version 3 wide prime id takes
/// `WIDE_PRIME_PUSH_EXTRA_BYTES` of that space. This is the one expression of it;
/// `max_tag_bytes` and `tag_push_data_that_fits` both read it from here.
const fn tag_space(wide_prime: bool) -> usize {
    MAX_COINBASE_TAG_SPACE - if wide_prime { WIDE_PRIME_PUSH_EXTRA_BYTES } else { 0 }
}

/// The most tag bytes (primary plus secondary) `script_sig` carries without shortening the
/// secondary tag: the tag space less the separator and the terminator `tag_push_data` adds.
pub const fn max_tag_bytes(wide_prime: bool) -> usize {
    tag_space(wide_prime) - TAG_MARKER_BYTES
}

pub(crate) fn tag_push_data(primary: &[u8], secondary: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(primary.len() + secondary.len() + TAG_MARKER_BYTES);
    data.put_slice(primary);
    if !secondary.is_empty() {
        data.put_u8(TAG_SEPARATOR);
        data.put_slice(secondary);
    }
    data.put_u8(TAG_END);
    data
}

pub(crate) const UNIQUE_ID_PUSH_TARGET_BYTE_AT: usize = 1;

pub(crate) fn unique_id_push(unique_id: u16, prime_id: &[u8]) -> Vec<u8> {
    let len = UNIQUE_ID_PUSH_DATA_SIZE_NO_PRIME + prime_id.len();
    debug_assert!(matches!(
        len,
        UNIQUE_ID_PUSH_DATA_SIZE_NO_PRIME
            | UNIQUE_ID_PUSH_DATA_SIZE_V1
            | UNIQUE_ID_PUSH_DATA_SIZE_V3
    ));
    let mut push = Vec::with_capacity(1 + len);
    push.put_u8(len as u8);
    push.put_u8(TARGET_BYTE_PLACEHOLDER);
    push.put_u16_le(unique_id);
    push.put_slice(prime_id);
    push
}

pub struct ScriptSigInputs<'a> {
    pub height: u32,
    pub tag_primary: &'a str,
    pub tag_secondary: &'a str,
    pub unique_id: u16,
    pub prime_id: u64,
    pub wide_prime: bool,
    pub datum_active: bool,
}

/// The scriptSig before the extranonce push, and the index of the target byte in it.
pub fn script_sig(t: &ScriptSigInputs<'_>) -> Option<(Vec<u8>, usize)> {
    let mut script = height_push(t.height);
    script.extend_from_slice(&encode_push(&tag_push_data_that_fits(t)?));
    let prime_id = if t.prime_id == 0 && !t.datum_active {
        &[][..]
    } else if t.wide_prime {
        &t.prime_id.to_le_bytes()[..]
    } else {
        &(t.prime_id as u32).to_le_bytes()[..]
    };
    let target_byte_index = script.len() + UNIQUE_ID_PUSH_TARGET_BYTE_AT;
    script.extend_from_slice(&unique_id_push(t.unique_id, prime_id));
    Some((script, target_byte_index))
}

fn tag_push_data_that_fits(t: &ScriptSigInputs<'_>) -> Option<Vec<u8>> {
    let tag0 = t.tag_primary.as_bytes();
    let tag1 = t.tag_secondary.as_bytes();
    let space = tag_space(t.wide_prime);
    let mut data = tag_push_data(tag0, tag1);
    if data.len() > space {
        let excess = data.len() - space;
        let kept = if tag1.len() > excess { &tag1[..tag1.len() - excess] } else { &[][..] };
        data = tag_push_data(tag0, kept);
    }
    (data.len() <= space).then_some(data)
}

/// What the pool reads back out of a coinbase's scriptSig: the index of the target byte in
/// the whole transaction, and the secondary tag the gateway pushed after the pool's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedScriptSig {
    pub target_byte_index: usize,
    pub tag_secondary: String,
}

/// The inverse of `script_sig`: locates the unique-id push carrying `prime_id` (32 bits wide
/// in a version 1 push, 64 in a version 3 push) and reads the tag push before it, which must
/// begin with `coinbase_tag` when one is set. None when either is missing.
pub fn parse_script_sig(
    tx: &CoinbaseTx,
    prime_id: u64,
    coinbase_tag: &str,
) -> Option<ParsedScriptSig> {
    let pushes = script_pushes(&tx.script_sig);
    let prime = prime_id.to_le_bytes();
    let unique_id_push = pushes.iter().position(|push| {
        let Some(id) = push.data.get(UNIQUE_ID_PUSH_DATA_SIZE_NO_PRIME..) else { return false };
        match push.data.len() {
            UNIQUE_ID_PUSH_DATA_SIZE_V1 => {
                u32::try_from(prime_id).is_ok() && id == &prime[..size_of::<u32>()]
            }
            UNIQUE_ID_PUSH_DATA_SIZE_V3 => id == prime,
            _ => false,
        }
    })?;
    let tag_push = unique_id_push.checked_sub(1).map(|i| pushes[i].data);
    let tag_secondary = if coinbase_tag.is_empty() {
        tag_push
            .and_then(|data| data.strip_prefix(&[TAG_SEPARATOR]))
            .map_or_else(String::new, decode_tag)
    } else {
        let (marker, rest) = tag_push
            .and_then(|data| data.strip_prefix(coinbase_tag.as_bytes()))
            .and_then(|after| after.split_first())
            .filter(|(marker, _)| matches!(**marker, TAG_END | TAG_SEPARATOR))?;
        if *marker == TAG_SEPARATOR { decode_tag(rest) } else { String::new() }
    };
    Some(ParsedScriptSig {
        target_byte_index: tx.script_sig_offset + pushes[unique_id_push].data_at,
        tag_secondary,
    })
}

fn decode_tag(bytes: &[u8]) -> String {
    let bytes = bytes.strip_suffix(&[TAG_END]).unwrap_or(bytes);
    String::from_utf8_lossy(bytes).chars().filter(|c| !c.is_control()).collect()
}

/// The template's size and weight limits, and the size and weight its transactions have
/// already used, which is what `output_budget` subtracts to size the coinbase.
#[derive(Clone, Copy, Debug)]
pub struct BlockLimits {
    pub sizelimit: u64,
    pub weightlimit: u64,
    pub txn_total_size: u64,
    pub txn_total_weight: u64,
}

impl BlockLimits {
    /// Limits no coinbase reaches, so `MAX_COINBASE_SECTION_LEN` alone bounds the outputs.
    pub(crate) const UNLIMITED: Self =
        Self { sizelimit: u64::MAX, weightlimit: u64::MAX, txn_total_size: 0, txn_total_weight: 0 };
}

pub struct CoinbaseSpec<'a> {
    pub coinbase_id: u8,
    pub script_sig: &'a [u8],
    pub target_byte_index_in_script: usize,
    pub enprefix: u16,
    pub witness_commitment: Option<&'a [u8]>,
    pub pool_payout_script: &'a [u8],
    pub coinbase_value: u64,
    pub outputs: &'a [TxOut],
    pub limits: BlockLimits,
    pub sigop_budget: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuiltCoinbase {
    pub section: CoinbaseSection,
    pub target_byte_index: usize,
}

/// The coinbase and the dictated outputs it carries, in the order they were given.
pub fn build(p: &CoinbaseSpec<'_>) -> (BuiltCoinbase, Vec<TxOut>) {
    let (included, paid) = select_outputs(p, output_budget(fixed_bytes(p), p.limits));
    (assemble(p, &included, paid), included)
}

/// The dictated outputs that fit `budget` bytes, the sigop budget and the coinbase value,
/// and the value they pay.
fn select_outputs(p: &CoinbaseSpec<'_>, budget: usize) -> (Vec<TxOut>, u64) {
    let mut included = Vec::new();
    let mut paid = 0u64;
    let mut remaining = budget;
    let mut sigops_left = p.sigop_budget;
    for o in p.outputs {
        if remaining < MIN_USEFUL_OUTPUT_ROOM || paid >= p.coinbase_value {
            break;
        }
        let cost = o.script_pubkey.len() + MIN_OUTPUT_SIZE;
        let sigops = output_sigop_cost(&o.script_pubkey);
        if paid.saturating_add(o.value) > p.coinbase_value
            || cost > remaining
            || sigops > sigops_left
        {
            continue;
        }
        remaining -= cost;
        sigops_left -= sigops;
        paid += o.value;
        included.push(o.clone());
    }
    (included, paid)
}

/// The coinbase carrying `included`, which pay `paid` of its value. This is the one
/// description of the layout: `fixed_bytes` measures what it emits rather than restating it.
fn assemble(p: &CoinbaseSpec<'_>, included: &[TxOut], paid: u64) -> BuiltCoinbase {
    let in_script = p.script_sig.len() <= SCRIPT_SIG_ROOM_FOR_EXTRANONCE;

    let mut coinb1 = COINBASE_TX_VERSION.to_le_bytes().to_vec();
    coinb1.extend_from_slice(&encode_compact_size(1));
    coinb1.extend_from_slice(&[0u8; HASH_SIZE]);
    coinb1.extend_from_slice(&NULL_OUTPOINT_INDEX);
    let n_out = included.len() as u64 + 1 + u64::from(p.witness_commitment.is_some());
    let script_sig_len = p.script_sig.len() + if in_script { EXTRANONCE_PUSH_SIZE } else { 0 };
    coinb1.extend_from_slice(&encode_compact_size(script_sig_len as u64));
    let target_byte_index = coinb1.len() + p.target_byte_index_in_script;
    coinb1.extend_from_slice(p.script_sig);

    let mut coinb2 = Vec::new();
    if in_script {
        coinb1.push(EXTRANONCE_PUSH_OPCODE);
        coinb1.extend_from_slice(&p.enprefix.to_be_bytes());
        coinb2.extend_from_slice(&SEQUENCE_FINAL);
        coinb2.extend_from_slice(&encode_compact_size(n_out));
    } else {
        coinb1.extend_from_slice(&SEQUENCE_FINAL);
        coinb1.extend_from_slice(&encode_compact_size(n_out + 1));
        coinb1.extend_from_slice(&0u64.to_le_bytes());
        coinb1.push((OP_RETURN_EXTRANONCE_OUTPUT_SIZE - MIN_OUTPUT_SIZE) as u8);
        coinb1.extend_from_slice(&[OP_RETURN, EXTRANONCE_PUSH_OPCODE]);
        coinb1.extend_from_slice(&p.enprefix.to_be_bytes());
    }
    for o in included {
        coinb2.extend_from_slice(&encode_output(o.value, &o.script_pubkey));
    }
    if p.coinbase_value > paid {
        coinb2.extend_from_slice(&encode_output(p.coinbase_value - paid, p.pool_payout_script));
    } else {
        coinb2.extend_from_slice(&encode_output(0, &PRUNABLE_OP_RETURN));
    }
    if let Some(wc) = p.witness_commitment {
        coinb2.extend_from_slice(&encode_output(0, wc));
    }
    coinb2.extend_from_slice(&[0u8; LOCK_TIME_SIZE]);
    let section = CoinbaseSection { coinbase_id: p.coinbase_id, coinb1, coinb2 };
    BuiltCoinbase { section, target_byte_index }
}

/// The bytes the coinbase occupies besides the dictated outputs, measured by assembling it
/// with none of them, so `assemble` is the only description of the layout. Two pieces the
/// section does not contain are added to that measurement: the extranonce, which a share
/// splices in when it assembles the transaction, and the bytes the output count grows by,
/// since it is written before the outputs it counts have been selected. Each is an upper
/// bound, so `output_budget` never returns more bytes than the block has left.
fn fixed_bytes(p: &CoinbaseSpec<'_>) -> usize {
    /// The pool's payout output, the witness commitment, and the OP_RETURN the extranonce is
    /// written to when the scriptSig cannot hold it.
    const MOST_UNDICTATED_OUTPUTS: u64 = 3;

    let section = assemble(p, &[], 0).section;
    let count_growth = encode_compact_size(p.outputs.len() as u64 + MOST_UNDICTATED_OUTPUTS).len()
        - encode_compact_size(MOST_UNDICTATED_OUTPUTS).len();
    section.coinb1.len() + EXTRANONCE_SIZE + section.coinb2.len() + count_growth
}

/// The bytes a block's coinbase may spend on dictated outputs: `limits` less what its
/// transactions, the header and the transaction count use, capped at the largest coinbase
/// section the pool accepts, less what the coinbase occupies besides those outputs.
fn output_budget(fixed_bytes: usize, limits: BlockLimits) -> usize {
    let around = (crate::header::HEADER_V2_SIZE + MAX_TXN_COUNT_SIZE) as u64;
    let size_used = limits.txn_total_size + around + COINBASE_WITNESS_BYTES;
    let by_size = limits.sizelimit.saturating_sub(size_used);
    let weight_used =
        limits.txn_total_weight + WITNESS_SCALE_FACTOR * around + COINBASE_WITNESS_BYTES;
    let by_weight = limits.weightlimit.saturating_sub(weight_used) / WITNESS_SCALE_FACTOR;
    let total = by_size.min(by_weight).min(MAX_COINBASE_SECTION_LEN as u64) as usize;
    total.saturating_sub(fixed_bytes)
}

pub fn output_sigop_cost(script: &[u8]) -> u64 {
    const MAX_PUBKEYS_PER_MULTISIG: u64 = 20;

    script_ops(script)
        .map(|op| match op.opcode {
            OP_CHECKSIG | OP_CHECKSIGVERIFY => WITNESS_SCALE_FACTOR,
            OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                MAX_PUBKEYS_PER_MULTISIG * WITNESS_SCALE_FACTOR
            }
            _ => 0,
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::transaction::parse_coinbase;
    use crate::fixtures::{ScriptSigTags, p2pkh, p2wpkh};

    fn tagging(height: u32) -> ScriptSigInputs<'static> {
        ScriptSigInputs {
            height,
            tag_primary: "RATUM",
            tag_secondary: "e2e",
            unique_id: 4242,
            prime_id: 7,
            wide_prime: false,
            datum_active: true,
        }
    }

    #[test]
    fn script_sig_layout_is_what_the_pool_parses() {
        let (s, target_byte_index) = script_sig(&tagging(21)).unwrap();
        let pushes = script_pushes(&s);
        assert_eq!(pushes.len(), 3);
        assert_eq!(pushes[0].data, &[21][..]);
        assert_eq!(pushes[1].data, b"RATUM\x0fe2e\x00");
        assert_eq!(pushes[2].data.len(), 7);
        assert_eq!(pushes[2].data_at, target_byte_index);
        assert_eq!(&pushes[2].data[3..], &7u32.to_le_bytes());
        assert_eq!(&pushes[2].data[1..3], &4242u16.to_le_bytes());
        assert_eq!(s[target_byte_index], 0xff);

        let mut t = tagging(21);
        t.tag_secondary = "";
        let (s, _) = script_sig(&t).unwrap();
        assert_eq!(script_pushes(&s)[1].data, b"RATUM\x00");

        t.tag_primary = "";
        let (s, target_byte_index) = script_sig(&t).unwrap();
        let pushes = script_pushes(&s);
        assert_eq!(pushes.len(), 3);
        assert_eq!(pushes[1].data, b"\x00");
        assert_eq!(pushes[2].data_at, target_byte_index);
    }

    #[test]
    fn a_short_unique_id_push_without_a_pool() {
        let mut t = tagging(21);
        t.prime_id = 0;
        t.datum_active = false;
        let (s, target_byte_index) = script_sig(&t).unwrap();
        let pushes = script_pushes(&s);
        assert_eq!(pushes[2].data.len(), 3);
        assert_eq!(pushes[2].data_at, target_byte_index);
    }

    fn spec<'a>(
        script: &'a [u8],
        target_byte_index: usize,
        outputs: &'a [TxOut],
        wc: Option<&'a [u8]>,
    ) -> CoinbaseSpec<'a> {
        CoinbaseSpec {
            coinbase_id: 1,
            script_sig: script,
            target_byte_index_in_script: target_byte_index,
            enprefix: 0xb10c,
            witness_commitment: wc,
            pool_payout_script: &[
                0x00, 0x14, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
            ],
            coinbase_value: 312_500_000,
            outputs,
            limits: BlockLimits::UNLIMITED,
            sigop_budget: 80_000,
        }
    }

    #[test]
    fn output_sigop_cost_counts_legacy_outputs_times_four() {
        assert_eq!(output_sigop_cost(&p2wpkh(1)), 0);
        assert_eq!(output_sigop_cost(&p2pkh(1)), 4);
        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend_from_slice(&[0x33; 32]);
        assert_eq!(output_sigop_cost(&p2tr), 0);
        let mut multisig = vec![0x51, 0x21];
        multisig.extend_from_slice(&[0xac; 33]);
        multisig.extend_from_slice(&[0x51, 0xae]);
        assert_eq!(output_sigop_cost(&multisig), 80);
        assert_eq!(output_sigop_cost(&[0x6a, 0x02, 0xac, 0xae]), 0);
        assert_eq!(output_sigop_cost(&[]), 0);
    }

    #[test]
    fn outputs_past_the_sigop_budget_are_left_out() {
        let (script, target_byte_index) = script_sig(&tagging(21)).unwrap();
        let outputs = vec![
            TxOut { value: 100_000_000, script_pubkey: p2pkh(1) },
            TxOut { value: 50_000_000, script_pubkey: p2pkh(2) },
            TxOut { value: 10_000_000, script_pubkey: p2wpkh(3) },
        ];
        let mut p = spec(&script, target_byte_index, &outputs, None);
        p.sigop_budget = 4;
        let (_, included) = build(&p);
        assert_eq!(included.len(), 2);
        assert_eq!(included[0].script_pubkey, p2pkh(1));
        assert_eq!(included[1].value, 10_000_000);
        p.sigop_budget = 0;
        let (_, included) = build(&p);
        assert_eq!(included.len(), 1, "only the segwit output");
    }

    #[test]
    fn the_output_budget_is_the_templates_room_capped_at_the_pools_section_limit() {
        let size_used = 85 + 84 + 36;
        let weight_used = 340 + 336 + 36;
        let limits = |sizelimit, weightlimit| BlockLimits {
            sizelimit,
            weightlimit,
            txn_total_size: 0,
            txn_total_weight: 0,
        };
        assert_eq!(
            output_budget(100, limits(4_000_000, 4_000_000)),
            MAX_COINBASE_SECTION_LEN - 100
        );
        assert_eq!(output_budget(100, limits(4_000_000, weight_used + 4 * 1_000)), 900);
        assert_eq!(output_budget(100, limits(size_used + 500, 4_000_000)), 400);
        assert_eq!(output_budget(100, limits(size_used, 4_000_000)), 0);
        assert_eq!(
            output_budget(
                100,
                BlockLimits { txn_total_weight: 4_000, ..limits(4_000_000, 4_000_000) }
            ),
            output_budget(100, limits(4_000_000, 4_000_000 - 4_000)),
            "a template's transactions spend the same weight as a lower limit"
        );
    }

    /// `fixed_bytes` drives the output budget, and the block weight limit is what it keeps
    /// the coinbase under. It is derived from `assemble`, so this pins that derivation
    /// against the bytes `assemble` actually emits, across both scriptSig lengths, with and
    /// without a witness commitment, and over the output counts where the count's CompactSize
    /// widens.
    #[test]
    fn fixed_bytes_covers_everything_the_coinbase_holds_besides_the_dictated_outputs() {
        let wc =
            [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed].into_iter().chain([0u8; 32]).collect::<Vec<_>>();
        let outputs: Vec<TxOut> =
            (0..600u16).map(|i| TxOut { value: 1_000, script_pubkey: p2wpkh(i as u8) }).collect();
        for t in [tagging(21), long_tagging()] {
            let (script, target_byte_index) = script_sig(&t).unwrap();
            for commitment in [None, Some(&wc[..])] {
                for n in [0usize, 1, 2, 251, 252, 253, 254, 600] {
                    let p = spec(&script, target_byte_index, &outputs[..n], commitment);
                    let (cb, included) = build(&p);
                    let tx = cb.section.assemble(&[0u8; EXTRANONCE_SIZE]);
                    let dictated: usize =
                        included.iter().map(|o| o.script_pubkey.len() + MIN_OUTPUT_SIZE).sum();
                    assert!(
                        tx.len() - dictated <= fixed_bytes(&p),
                        "{n} outputs, commitment {}: the coinbase holds {} bytes besides them, \
                         over the {} fixed_bytes reserved",
                        commitment.is_some(),
                        tx.len() - dictated,
                        fixed_bytes(&p)
                    );
                }
            }
        }
    }

    fn long_tagging() -> ScriptSigInputs<'static> {
        let mut t = tagging(21);
        t.tag_primary = "RATUM is a pool for the Bitcoin Knots BLAKE2b hardfork";
        t.tag_secondary = "a secondary tag of some length";
        t
    }

    #[test]
    fn the_assembled_coinbase_parses_and_locates_the_target_byte() {
        let wc = [
            0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let outputs = vec![
            TxOut { value: 100_000_000, script_pubkey: p2wpkh(1) },
            TxOut { value: 50_000_000, script_pubkey: p2wpkh(2) },
        ];
        for t in [tagging(21), long_tagging()] {
            let (script, target_byte_index_in_script) = script_sig(&t).unwrap();
            let force = script.len() > SCRIPT_SIG_ROOM_FOR_EXTRANONCE;
            let (cb, included) =
                build(&spec(&script, target_byte_index_in_script, &outputs, Some(&wc)));
            assert_eq!(included.len(), 2);
            let tx = cb.section.assemble(&[0u8; 12]);
            assert_eq!(tx[cb.target_byte_index], 0xff);
            let parsed = parse_coinbase(&tx).unwrap();
            assert!(!parsed.has_witness);
            let pushes = script_pushes(&parsed.script_sig);
            let unique_id_push = pushes.iter().find(|p| p.data.len() == 7).unwrap();
            assert_eq!(parsed.script_sig_offset + unique_id_push.data_at, cb.target_byte_index);
            let total: u64 = parsed.outputs.iter().map(|o| o.value).sum();
            assert_eq!(total, 312_500_000);
            assert_eq!(parsed.outputs.len(), if force { 5 } else { 4 });
            if force {
                assert_eq!(parsed.outputs[0].value, 0);
                assert_eq!(parsed.outputs[0].script_pubkey.len(), 16);
                assert_eq!(parsed.outputs[0].script_pubkey[0], 0x6a);
            }
            assert_eq!(parsed.outputs.last().unwrap().script_pubkey, wc.to_vec());
            assert_eq!(
                parsed.script_sig.len(),
                if force { script.len() } else { script.len() + 15 }
            );
        }
    }

    #[test]
    fn the_wide_prime_push_takes_four_bytes_from_the_tags_and_stays_within_100() {
        let (v1, _) = script_sig(&tagging(21)).unwrap();
        let mut t = tagging(21);
        t.wide_prime = true;
        let (v3, _) = script_sig(&t).unwrap();
        assert_eq!(v3.len(), v1.len() + 4);
        assert_eq!(script_pushes(&v3).last().unwrap().data.len(), 11);

        let mut t = long_tagging();
        let (v1, _) = script_sig(&t).unwrap();
        t.wide_prime = true;
        let (v3, _) = script_sig(&t).unwrap();
        assert!(v1.len() <= 100);
        assert!(
            v3.len() <= 100,
            "wide prime push must not push the scriptSig past 100: {}",
            v3.len()
        );
        let tags = |s: &[u8]| script_pushes(s)[1].data.len();
        assert_eq!(
            tags(&v3) + 4,
            tags(&v1),
            "v3 tag space + 4 != v1 tag space (the u64 prime id push costs 4 bytes)"
        );
    }

    #[test]
    fn a_long_script_sig_moves_the_extranonce_to_an_output() {
        let (script, target_byte_index) = script_sig(&long_tagging()).unwrap();
        assert!(script.len() > SCRIPT_SIG_ROOM_FOR_EXTRANONCE);
        assert!(script.len() <= MAX_COINBASE_SCRIPT_SIG_LEN);
        let (cb, _) = build(&spec(&script, target_byte_index, &[], None));
        let tx = cb.section.assemble(&[0u8; 12]);
        let parsed = parse_coinbase(&tx).unwrap();
        assert_eq!(parsed.outputs.len(), 2);
        assert_eq!(parsed.outputs[0].script_pubkey[0], 0x6a);
    }

    #[test]
    fn a_split_taking_the_whole_value_leaves_the_pool_a_prunable_output() {
        let (script, target_byte_index) = script_sig(&tagging(21)).unwrap();
        let outputs = vec![
            TxOut { value: 312_500_000 - 100, script_pubkey: p2wpkh(1) },
            TxOut { value: 100, script_pubkey: p2wpkh(2) },
        ];
        let (cb, included) = build(&spec(&script, target_byte_index, &outputs, None));
        assert_eq!(included.len(), 2, "an output that exactly exhausts the value is still paid");
        let parsed = parse_coinbase(&cb.section.assemble(&[0u8; 12])).unwrap();
        assert_eq!(parsed.outputs.iter().map(|o| o.value).sum::<u64>(), 312_500_000);
        let last = parsed.outputs.last().unwrap();
        assert_eq!(last.value, 0);
        assert_eq!(last.script_pubkey, PRUNABLE_OP_RETURN.to_vec(), "nothing is left for the pool");
    }

    #[test]
    fn outputs_over_the_value_are_left_out_and_the_rest_reaches_the_pool() {
        let (script, target_byte_index) = script_sig(&tagging(21)).unwrap();
        let outputs = vec![
            TxOut { value: 300_000_000, script_pubkey: p2wpkh(1) },
            TxOut { value: 50_000_000, script_pubkey: p2wpkh(2) },
            TxOut { value: 10_000_000, script_pubkey: p2wpkh(3) },
        ];
        let p = spec(&script, target_byte_index, &outputs, None);
        let (cb, included) = build(&p);
        assert_eq!(included.len(), 2, "the 50M output does not fit under the value");
        assert_eq!(included[1].value, 10_000_000);
        let parsed = parse_coinbase(&cb.section.assemble(&[0u8; 12])).unwrap();
        assert_eq!(parsed.outputs[2].value, 2_500_000);
    }

    #[test]
    fn outputs_past_the_byte_budget_are_left_out() {
        let (script, target_byte_index) = script_sig(&tagging(21)).unwrap();
        let outputs = vec![
            TxOut { value: 1, script_pubkey: p2wpkh(1) },
            TxOut { value: 2, script_pubkey: p2wpkh(2) },
            TxOut { value: 3, script_pubkey: p2wpkh(3) },
        ];
        let p = spec(&script, target_byte_index, &outputs, None);
        let cost = p2wpkh(1).len() + MIN_OUTPUT_SIZE;
        assert_eq!(select_outputs(&p, 2 * cost).0.len(), 2);
        assert_eq!(select_outputs(&p, 3 * cost).0.len(), 3);
        assert_eq!(select_outputs(&p, MIN_USEFUL_OUTPUT_ROOM - 1).0.len(), 0);
    }

    fn parsed(prime_id: u32, coinbase_tag: &str, tag_secondary: &str) -> ParsedScriptSig {
        let tagging = ScriptSigTags { tag_primary: coinbase_tag, tag_secondary, prime_id };
        let cb = crate::fixtures::coinbase(&tagging, &p2wpkh(0xee), &[], 312_500_000);
        let tx = cb.section.assemble(&[0u8; EXTRANONCE_SIZE]);
        let coinbase = parse_coinbase(&tx).expect("a parseable coinbase");
        let found = parse_script_sig(&coinbase, u64::from(prime_id), coinbase_tag)
            .expect("the pool tag is present");
        assert_eq!(
            found.target_byte_index, cb.target_byte_index,
            "the target byte is where the builder placed it"
        );
        assert_eq!(tx[found.target_byte_index], TARGET_BYTE_PLACEHOLDER);
        found
    }

    #[test]
    fn the_pool_reads_the_target_byte_index_and_the_secondary_tag_back() {
        assert_eq!(parsed(1, "RATUM", "bob").tag_secondary, "bob");
        assert_eq!(parsed(1, "RATUM", "").tag_secondary, "", "the pool tag alone");
        assert_eq!(parsed(1, "", "bob").tag_secondary, "bob", "no pool tag declared");
        assert_eq!(parsed(1, "", "").tag_secondary, "");
        assert_eq!(parsed(0x1234_5678, "a long pool tag", "x").tag_secondary, "x");
    }

    #[test]
    fn a_script_sig_of_another_pool_does_not_parse() {
        let tagging = ScriptSigTags { tag_primary: "RATUM", tag_secondary: "bob", prime_id: 1 };
        let cb = crate::fixtures::coinbase(&tagging, &p2wpkh(0xee), &[], 312_500_000);
        let coinbase = parse_coinbase(&cb.section.assemble(&[0u8; EXTRANONCE_SIZE])).unwrap();
        assert!(parse_script_sig(&coinbase, 1, "RATUM").is_some());
        assert_eq!(parse_script_sig(&coinbase, 2, "RATUM"), None, "another prime id");
        assert_eq!(parse_script_sig(&coinbase, 1, "SOMEONEELSE"), None, "another pool tag");
        assert_eq!(parse_script_sig(&coinbase, 1, "RATU"), None, "a prefix of the tag");
        assert_eq!(
            parse_script_sig(&coinbase, 1 | 1 << 32, "RATUM"),
            None,
            "a 64-bit prime id is not found in a 32-bit push"
        );
    }

    #[test]
    fn decode_tag_removes_the_terminator_and_control_characters() {
        assert_eq!(decode_tag(b"bob\x00"), "bob");
        assert_eq!(decode_tag(b"bob"), "bob", "a push without the terminator");
        assert_eq!(decode_tag(b"a\x01b\x00"), "ab");
        assert_eq!(decode_tag(&[0xff, 0x41]), "\u{fffd}A", "invalid UTF-8 is replaced");
    }
}
