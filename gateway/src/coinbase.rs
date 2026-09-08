//! The generation transaction, in the layout the C gateway writes and the pool's verifier
//! parses (`datum_coinbaser.c`; `ratum_prime::verify::locate_pot_byte` and `check_outputs`).
//!
//! The transaction is split in two around twelve bytes the assembler inserts (zero in a
//! version 2 job, where the header carries the extranonce instead):
//!
//! ```text
//! coinb1: version, one input with the null outpoint, scriptSig length, scriptSig:
//!           BIP34 height push, tag push,
//!           uid push (0xFF PoT placeholder, unique id, prime id), PUSH 14, enprefix (2)
//!         [12 bytes]
//! coinb2: sequence, output count, outputs, lock time
//! ```
//!
//! When the scriptSig has no room for the 15-byte extranonce push it goes into a zero-value
//! OP_RETURN output instead, and coinb1 then ends inside that output's script.

use crate::template::Template;
use ratum::bitcoin::opcode::{
    MAX_DIRECT_PUSH_OPCODE, OP_0, OP_16, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY, OP_CHECKSIG,
    OP_CHECKSIGVERIFY, OP_N_BASE, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4, OP_RETURN,
};
use ratum::bitcoin::{
    HASH_SIZE, LOCK_TIME_SIZE, MIN_OUTPUT_SIZE, NULL_OUTPOINT_INDEX, OUTPOINT_SIZE, SEQUENCE_FINAL,
    SEQUENCE_SIZE, TX_VERSION_SIZE, WITNESS_SCALE_FACTOR, encode_compact_size, encode_output,
    encode_push,
};
use ratum::datum::coinbase::{
    EXTRANONCE_PUSH_SIZE, POT_TARGET_PLACEHOLDER, TAG_END, TAG_MARKER_BYTES, TAG_SEPARATOR,
    UID_PUSH_SIZE_NO_PRIME, UID_PUSH_SIZE_V1, UID_PUSH_SIZE_V3,
};
use ratum::datum::messages::CoinbaseOutput;
use ratum::datum::share::{EXTRANONCE_SIZE, MAX_COINBASE_SECTION_BYTES};

/// The consensus limit on a coinbase's scriptSig: `tx.vin[0].scriptSig.size() > 100` is
/// `bad-cb-length` in `consensus/tx_check.cpp`.
pub const MAX_COINBASE_SCRIPT_SIG: usize = 100;

/// The scriptSig length up to which the extranonce push fits inside it.
pub const SCRIPT_SIG_ROOM_FOR_EXTRANONCE: usize = MAX_COINBASE_SCRIPT_SIG - EXTRANONCE_PUSH_SIZE;

/// The zero-value output that carries the extranonce when the scriptSig has no room: the
/// value and the one-byte script length, then a 16-byte script of `OP_RETURN` and the same
/// push the scriptSig would have held.
const OP_RETURN_EXTRANONCE_OUTPUT_SIZE: usize = MIN_OUTPUT_SIZE + 1 + EXTRANONCE_PUSH_SIZE;

/// What the OP_RETURN form costs over the in-scriptSig one, the C gateway's "it costs 10
/// extra bytes to do the OP_RETURN based extranonce".
const OP_RETURN_EXTRANONCE_EXTRA_BYTES: usize =
    OP_RETURN_EXTRANONCE_OUTPUT_SIZE - EXTRANONCE_PUSH_SIZE;

/// The bytes a coinbase occupies other than its scriptSig, the pool payout script and the
/// dictated outputs, as `datum_coinbaser.c` counts them (`total static bytes = 124`):
///
/// ```text
///  4  version
///  1  input count
/// 36  the null outpoint
///  1  scriptSig length
///  4  sequence
///  3  output count, counted at its three-byte CompactSize size
/// 15  the extranonce push
///  9  the pool output's value and script length
/// 47  the witness commitment output (8 value, 1 length, and the 38-byte script the node's
///     `default_witness_commitment` always is: OP_RETURN and a 36-byte push)
///  4  lock time
/// ```
///
/// The output count is one byte up to 252 outputs; counted at three so a coinbase built to
/// the budget never exceeds the room `output_budget` reported.
fn static_bytes(witness_commitment_len: usize) -> usize {
    /// The one input: its count, the null outpoint and the one-byte scriptSig length.
    const NULL_INPUT: usize = 1 + OUTPOINT_SIZE + 1;
    /// The output count, at the three-byte CompactSize size.
    const OUTPUT_COUNT: usize = 3;
    TX_VERSION_SIZE
        + NULL_INPUT
        + SEQUENCE_SIZE
        + OUTPUT_COUNT
        + EXTRANONCE_PUSH_SIZE
        + MIN_OUTPUT_SIZE
        + (MIN_OUTPUT_SIZE + witness_commitment_len)
        + LOCK_TIME_SIZE
}

/// The coinbase's bytes before its dictated outputs: the static framing, the scriptSig, the
/// pool payout script, and the extra an OP_RETURN extranonce output costs when the scriptSig
/// has no room for the push.
pub fn fixed_bytes(
    script_sig_len: usize,
    pool_script_len: usize,
    witness_commitment_len: usize,
) -> usize {
    static_bytes(witness_commitment_len)
        + script_sig_len
        + pool_script_len
        + if script_sig_len > SCRIPT_SIG_ROOM_FOR_EXTRANONCE {
            OP_RETURN_EXTRANONCE_EXTRA_BYTES
        } else {
            0
        }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coinbase {
    pub coinb1: Vec<u8>,
    pub coinb2: Vec<u8>,
}

impl Coinbase {
    /// The transaction with `middle` (the extranonce bytes) between the halves.
    pub fn assemble(&self, middle: &[u8; EXTRANONCE_SIZE]) -> Vec<u8> {
        let mut tx = Vec::with_capacity(self.coinb1.len() + EXTRANONCE_SIZE + self.coinb2.len());
        tx.extend_from_slice(&self.coinb1);
        tx.extend_from_slice(middle);
        tx.extend_from_slice(&self.coinb2);
        tx
    }
}

pub struct Tagging<'a> {
    pub height: u32,
    pub tag_primary: &'a str,
    pub tag_secondary: &'a str,
    pub unique_id: u16,
    pub prime_id: u64,
    /// Write the 11-byte push carrying the full 64-bit prime id (the version 3 protocol) rather
    /// than the 7-byte push with a 32-bit prime id (version 1).
    pub wide_prime: bool,
    /// Whether a pool dictates the coinbase; with `prime_id` 0 and no pool the uid push is
    /// the short form.
    pub datum_active: bool,
}

/// The BIP34 height push as `CScript() << nHeight`: OP_0, OP_1..OP_16, or a minimal
/// little-endian data push with a zero byte appended when the top bit is set.
pub fn height_push(height: u32) -> Vec<u8> {
    /// The top bit of a `CScriptNum`'s most significant byte, which reads as the sign.
    const SIGN_BIT: u8 = 0x80;
    /// The largest height `OP_1`..`OP_16` encode on their own.
    const SMALL_INT_MAX: u32 = (OP_16 - OP_N_BASE) as u32;

    match height {
        0 => vec![OP_0],
        1..=SMALL_INT_MAX => vec![OP_N_BASE + height as u8],
        h => {
            let mut bytes = Vec::new();
            let mut v = h;
            while v > 0 {
                bytes.push(v as u8);
                v >>= u8::BITS;
            }
            if bytes.last().is_some_and(|b| b & SIGN_BIT != 0) {
                bytes.push(0);
            }
            let mut out = vec![bytes.len() as u8];
            out.extend_from_slice(&bytes);
            out
        }
    }
}

/// The scriptSig without the extranonce push, and the offset of the PoT placeholder in it.
pub fn script_sig(t: &Tagging<'_>) -> Result<(Vec<u8>, usize), String> {
    let mut script = height_push(t.height);
    {
        let tag0 = t.tag_primary.as_bytes();
        let mut tag1 = t.tag_secondary.as_bytes();
        // The version 3 prime push is 11 bytes rather than 7, so the tags have 4 fewer bytes
        // of the scriptSig to fit in (the C gateway's MAX_COINBASE_TAG_SPACE went 86 to 82).
        let tag_space = crate::config::MAX_COINBASE_TAG_SPACE
            - if t.wide_prime { crate::config::WIDE_PRIME_PUSH_EXTRA_BYTES } else { 0 };
        let mut k = tag0.len() + tag1.len() + TAG_MARKER_BYTES;
        if tag1.is_empty() {
            k -= 1;
            if tag0.is_empty() {
                k -= 1;
            }
        }
        if k > tag_space {
            let excess = k - tag_space;
            if tag1.len() > excess {
                tag1 = &tag1[..tag1.len() - excess];
                k = tag_space;
            } else if !tag1.is_empty() {
                k -= tag1.len() + 1;
                tag1 = &[];
            }
            if k > tag_space {
                return Err("the coinbase tags do not fit".into());
            }
        }
        if k > 0 {
            let mut data = Vec::with_capacity(k);
            if !tag0.is_empty() {
                data.extend_from_slice(tag0);
                data.push(if tag1.is_empty() { TAG_END } else { TAG_SEPARATOR });
            } else if !tag1.is_empty() {
                data.push(TAG_SEPARATOR);
            }
            if !tag1.is_empty() {
                data.extend_from_slice(tag1);
                data.push(TAG_END);
            }
            script.extend_from_slice(&encode_push(&data));
        } else {
            // A one-byte push of TAG_END, so the uid push that follows is not read as a tag.
            script.extend_from_slice(&encode_push(&[TAG_END]));
        }
    }
    // The uid push: its size names which prime id form follows the placeholder and unique id.
    let (push_size, prime_id) = if t.prime_id == 0 && !t.datum_active {
        (UID_PUSH_SIZE_NO_PRIME, &[][..])
    } else if t.wide_prime {
        (UID_PUSH_SIZE_V3, &t.prime_id.to_le_bytes()[..])
    } else {
        (UID_PUSH_SIZE_V1, &(t.prime_id as u32).to_le_bytes()[..])
    };
    script.push(push_size as u8);
    let pot_index = script.len();
    script.push(POT_TARGET_PLACEHOLDER);
    script.extend_from_slice(&t.unique_id.to_le_bytes());
    script.extend_from_slice(prime_id);
    debug_assert_eq!(script.len(), pot_index + push_size);
    Ok((script, pot_index))
}

pub struct Params<'a> {
    pub script_sig: &'a [u8],
    pub pot_index_in_script: usize,
    pub enprefix: u16,
    /// The witness commitment output script; `None` for a subsidy-only coinbase.
    pub witness_commitment: Option<&'a [u8]>,
    pub pool_script: &'a [u8],
    pub coinbase_value: u64,
    pub outputs: &'a [CoinbaseOutput],
    /// The bytes available for `outputs`; each costs its script length plus nine.
    pub output_budget: usize,
    /// The sigop cost available for `outputs` (`output_sigop_cost`): the block's limit less
    /// its transactions and the pool script's output.
    pub sigop_budget: u64,
    pub force_op_return_extranonce: bool,
}

/// The generation transaction's `nVersion`, as `datum_coinbaser.c` writes it.
const COINBASE_TX_VERSION: u32 = 1;
/// The script of the prunable output that stands in for the pool's when the dictated
/// outputs take the whole coinbase value: `OP_RETURN` and a one-byte push of zero.
const PRUNABLE_OP_RETURN: [u8; 3] = [OP_RETURN, 0x01, 0x00];

/// The room below which `build` stops considering further outputs, matching the C gateway's
/// `if (i < 30) break;`: no standard output fits, the smallest being a 22-byte P2WPKH script
/// and its nine bytes of value and length.
const MIN_USEFUL_OUTPUT_ROOM: usize = 30;

/// Build a coinbase. Returns it, the offset of the PoT byte in the assembled transaction, and
/// the outputs that were included.
pub fn build(p: &Params<'_>) -> (Coinbase, usize, Vec<CoinbaseOutput>) {
    let in_script =
        p.script_sig.len() <= SCRIPT_SIG_ROOM_FOR_EXTRANONCE && !p.force_op_return_extranonce;

    let mut included = Vec::new();
    let mut paid = 0u64;
    let mut remaining = p.output_budget;
    let mut sigops_left = p.sigop_budget;
    for o in p.outputs {
        if remaining < MIN_USEFUL_OUTPUT_ROOM || paid >= p.coinbase_value {
            break;
        }
        let cost = o.script.len() + MIN_OUTPUT_SIZE;
        let sigops = output_sigop_cost(&o.script);
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

    // Version 1, then one input spending the null outpoint.
    let mut coinb1 = COINBASE_TX_VERSION.to_le_bytes().to_vec();
    coinb1.extend_from_slice(&encode_compact_size(1));
    coinb1.extend_from_slice(&[0u8; HASH_SIZE]);
    coinb1.extend_from_slice(&NULL_OUTPOINT_INDEX);
    let n_out = included.len() as u64 + 1 + u64::from(p.witness_commitment.is_some());
    // The push opcode covering the enprefix and the extranonce, one byte short of the
    // 15-byte push because the opcode itself is not part of the data.
    let extranonce_push_opcode = (EXTRANONCE_PUSH_SIZE - 1) as u8;
    let pot_index;
    let mut coinb2 = Vec::new();
    if in_script {
        let script_sig_len = (p.script_sig.len() + EXTRANONCE_PUSH_SIZE) as u64;
        coinb1.extend_from_slice(&encode_compact_size(script_sig_len));
        pot_index = coinb1.len() + p.pot_index_in_script;
        coinb1.extend_from_slice(p.script_sig);
        coinb1.push(extranonce_push_opcode);
        coinb1.extend_from_slice(&p.enprefix.to_be_bytes());
        coinb2.extend_from_slice(&SEQUENCE_FINAL);
        coinb2.extend_from_slice(&encode_compact_size(n_out));
    } else {
        coinb1.extend_from_slice(&encode_compact_size(p.script_sig.len() as u64));
        pot_index = coinb1.len() + p.pot_index_in_script;
        coinb1.extend_from_slice(p.script_sig);
        coinb1.extend_from_slice(&SEQUENCE_FINAL);
        // The extranonce OP_RETURN is the first output, so coinb1 ends inside its script and
        // the assembler's twelve bytes land in the data push.
        coinb1.extend_from_slice(&encode_compact_size(n_out + 1));
        coinb1.extend_from_slice(&0u64.to_le_bytes());
        coinb1.push((OP_RETURN_EXTRANONCE_OUTPUT_SIZE - MIN_OUTPUT_SIZE) as u8);
        coinb1.extend_from_slice(&[OP_RETURN, extranonce_push_opcode]);
        coinb1.extend_from_slice(&p.enprefix.to_be_bytes());
    }
    for o in &included {
        coinb2.extend_from_slice(&encode_output(o.value, &o.script));
    }
    if p.coinbase_value > paid {
        coinb2.extend_from_slice(&encode_output(p.coinbase_value - paid, p.pool_script));
    } else {
        // Every satoshi went to the dictated outputs, but an output was already counted for
        // the pool; make it a prunable zero-value OP_RETURN rather than shifting the count.
        coinb2.extend_from_slice(&encode_output(0, &PRUNABLE_OP_RETURN));
    }
    if let Some(wc) = p.witness_commitment {
        coinb2.extend_from_slice(&encode_output(0, wc));
    }
    coinb2.extend_from_slice(&[0u8; LOCK_TIME_SIZE]);
    (Coinbase { coinb1, coinb2 }, pot_index, included)
}

/// The coinbase id a pooled job's stratum job ids and shares carry. There is one: under the
/// version 2 header the mining machine receives a fixed 35-byte `coinb1` (three zero bytes
/// and H2) and never the coinbase itself, so a job has no size class to name. The C
/// gateway's indices 1..5 named the coinbase size classes SHA256d miners' firmware
/// imposed, since those miners reconstruct and hash the coinbase. `COINBASE_SUBSIDY_ONLY`
/// (0xff) names the other coinbase a job holds.
pub const COINBASE_POOLED: u8 = 1;

/// The most bytes a coinbase may hold whatever room the template leaves: the pool refuses a
/// coinbase section over `MAX_COINBASE_SECTION_BYTES`. `output_budget` takes this as the
/// transaction's size with `fixed_bytes` counting the framing at its three-byte-output-count
/// size (`job::coinbase_set`), and the section omits the `EXTRANONCE_SIZE` (12) bytes the
/// transaction holds, so a section built to this is at least twelve bytes under the pool's
/// limit.
pub const MAX_COINBASE_BYTES: usize = MAX_COINBASE_SECTION_BYTES;

/// The bytes the template leaves for a coinbase's outputs beyond `fixed_bytes`: the block's
/// size and weight limits less its transactions (`datum_stratum_coinbase_fit_to_template`,
/// without the size class it also took), and at most `MAX_COINBASE_BYTES` in all. A coinbase
/// byte weighs four units, the transaction having no witness data. Under RDTS the node
/// reports the reduced weight limit (800,000); what its transactions leave unfilled is its
/// `-blockreservedweight` (8,000 by default), so a node serving a pool with many identities
/// is run with a larger one.
pub fn output_budget(fixed_bytes: usize, t: &Template) -> usize {
    // The block around the coinbase: the header and a transaction count of at most five
    // bytes, which weigh four units a byte like the coinbase itself.
    let around = (ratum::header::HEADER_V2_SIZE + MAX_TXN_COUNT_SIZE) as u64;
    let size_used = t.totals.size as u64 + around + COINBASE_WITNESS_BYTES;
    let by_size = t.sizelimit.saturating_sub(size_used);
    let weight_used =
        t.totals.weight as u64 + WITNESS_SCALE_FACTOR * around + COINBASE_WITNESS_BYTES;
    let by_weight = t.weightlimit.saturating_sub(weight_used) / WITNESS_SCALE_FACTOR;
    let room = by_size.min(by_weight).min(MAX_COINBASE_BYTES as u64) as usize;
    room.saturating_sub(fixed_bytes)
}

/// The largest CompactSize a block's transaction count occupies; `MAX_TXNS` needs three, but
/// the C gateway counts five and the difference is two bytes of coinbase room.
const MAX_TXN_COUNT_SIZE: usize = 5;

/// The witness the node adds to the coinbase: the marker and flag and a single 32-byte
/// reserved item with its count and length. These weigh one unit a byte, not four.
const COINBASE_WITNESS_BYTES: u64 = 36;

/// The sigop cost of an output script as the block limit counts it: legacy sigops times
/// four (`GetLegacySigOpCount` counts output scripts, and the coinbase's count is scaled by
/// `WITNESS_SCALE_FACTOR`). OP_CHECKSIG and OP_CHECKSIGVERIFY count one, OP_CHECKMULTISIG
/// and OP_CHECKMULTISIGVERIFY twenty (the inaccurate count the limit uses); push data is
/// skipped. A segwit output (P2WPKH, P2WSH, P2TR) costs nothing, a P2PKH output four.
pub fn output_sigop_cost(script: &[u8]) -> u64 {
    /// What `GetSigOpCount(false)` charges a CHECKMULTISIG whose key count it does not read.
    const MAX_PUBKEYS_PER_MULTISIG: u64 = 20;

    let mut cost = 0u64;
    let mut i = 0usize;
    while i < script.len() {
        let op = script[i];
        i += 1;
        let push = match op {
            0x01..=MAX_DIRECT_PUSH_OPCODE => usize::from(op),
            OP_PUSHDATA1 => {
                let n = script.get(i).map_or(0, |&b| usize::from(b));
                i += 1;
                n
            }
            OP_PUSHDATA2 => {
                let n = script
                    .get(i..i + size_of::<u16>())
                    .map_or(0, |b| usize::from(u16::from_le_bytes([b[0], b[1]])));
                i += size_of::<u16>();
                n
            }
            OP_PUSHDATA4 => {
                let n = script
                    .get(i..i + size_of::<u32>())
                    .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize);
                i += size_of::<u32>();
                n
            }
            OP_CHECKSIG | OP_CHECKSIGVERIFY => {
                cost += WITNESS_SCALE_FACTOR;
                0
            }
            OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                cost += MAX_PUBKEYS_PER_MULTISIG * WITNESS_SCALE_FACTOR;
                0
            }
            _ => 0,
        };
        i = i.saturating_add(push);
    }
    cost
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn height_pushes_match_bip34() {
        assert_eq!(height_push(0), vec![0x00]);
        assert_eq!(height_push(1), vec![0x51]);
        assert_eq!(height_push(16), vec![0x60]);
        assert_eq!(height_push(17), vec![0x01, 0x11]);
        assert_eq!(height_push(128), vec![0x02, 0x80, 0x00]);
        assert_eq!(height_push(840_000), vec![0x03, 0x40, 0xd1, 0x0c]);
    }

    fn tagging(height: u32) -> Tagging<'static> {
        Tagging {
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
        let (s, pot) = script_sig(&tagging(21)).unwrap();
        let pushes = ratum::bitcoin::script_pushes(&s);
        assert_eq!(pushes.len(), 3);
        assert_eq!(pushes[0].1, &[21][..]);
        assert_eq!(pushes[1].1, b"RATUM\x0fe2e\x00");
        assert_eq!(pushes[2].1.len(), 7);
        assert_eq!(pushes[2].0, pot);
        assert_eq!(&pushes[2].1[3..], &7u32.to_le_bytes());
        assert_eq!(&pushes[2].1[1..3], &4242u16.to_le_bytes());
        assert_eq!(s[pot], 0xff);

        let mut t = tagging(21);
        t.tag_secondary = "";
        let (s, _) = script_sig(&t).unwrap();
        assert_eq!(ratum::bitcoin::script_pushes(&s)[1].1, b"RATUM\x00");
    }

    #[test]
    fn a_short_uid_push_without_a_pool() {
        let mut t = tagging(21);
        t.prime_id = 0;
        t.datum_active = false;
        let (s, pot) = script_sig(&t).unwrap();
        let pushes = ratum::bitcoin::script_pushes(&s);
        assert_eq!(pushes[2].1.len(), 3);
        assert_eq!(pushes[2].0, pot);
    }

    fn params<'a>(
        script: &'a [u8],
        pot: usize,
        outputs: &'a [CoinbaseOutput],
        wc: Option<&'a [u8]>,
        force: bool,
    ) -> Params<'a> {
        Params {
            script_sig: script,
            pot_index_in_script: pot,
            enprefix: 0xb10c,
            witness_commitment: wc,
            pool_script: &[
                0x00, 0x14, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
            ],
            coinbase_value: 312_500_000,
            outputs,
            output_budget: 400,
            sigop_budget: 80_000,
            force_op_return_extranonce: force,
        }
    }

    fn p2pkh(tag: u8) -> Vec<u8> {
        let mut s = vec![0x76, 0xa9, 0x14];
        s.extend_from_slice(&[tag; 20]);
        s.extend_from_slice(&[0x88, 0xac]);
        s
    }

    #[test]
    fn output_sigop_cost_counts_legacy_outputs_times_four() {
        assert_eq!(output_sigop_cost(&ratum::fixtures::p2wpkh(1)), 0);
        assert_eq!(output_sigop_cost(&p2pkh(1)), 4);
        // P2TR: OP_1 then a 32-byte push.
        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend_from_slice(&[0x33; 32]);
        assert_eq!(output_sigop_cost(&p2tr), 0);
        // A bare 1-of-1 multisig: the pushed key's bytes are skipped, the CHECKMULTISIG
        // counts twenty.
        let mut multisig = vec![0x51, 0x21];
        multisig.extend_from_slice(&[0xac; 33]);
        multisig.extend_from_slice(&[0x51, 0xae]);
        assert_eq!(output_sigop_cost(&multisig), 80);
        // OP_RETURN data holding opcode bytes is a push, not sigops.
        assert_eq!(output_sigop_cost(&[0x6a, 0x02, 0xac, 0xae]), 0);
        assert_eq!(output_sigop_cost(&[]), 0);
    }

    #[test]
    fn outputs_past_the_sigop_budget_are_left_out() {
        let (script, pot) = script_sig(&tagging(21)).unwrap();
        let outputs = vec![
            CoinbaseOutput { value: 100_000_000, script: p2pkh(1) },
            CoinbaseOutput { value: 50_000_000, script: p2pkh(2) },
            CoinbaseOutput { value: 10_000_000, script: ratum::fixtures::p2wpkh(3) },
        ];
        let mut p = params(&script, pot, &outputs, None, false);
        p.sigop_budget = 4;
        let (_, _, included) = build(&p);
        // One P2PKH output fits the budget; the segwit output after the second costs none.
        assert_eq!(included.len(), 2);
        assert_eq!(included[0].script, p2pkh(1));
        assert_eq!(included[1].value, 10_000_000);
        p.sigop_budget = 0;
        let (_, _, included) = build(&p);
        assert_eq!(included.len(), 1, "only the segwit output");
    }

    #[test]
    fn the_output_budget_is_the_templates_room_capped_at_the_pools_section_limit() {
        let mut t = crate::template::tests::template();
        let size_used = t.totals.size as u64 + 85 + 84 + 36;
        let weight_used = t.totals.weight as u64 + 340 + 336 + 36;
        // Limits far above the transactions: the pool's section limit.
        t.sizelimit = 4_000_000;
        t.weightlimit = 4_000_000;
        assert_eq!(output_budget(100, &t), MAX_COINBASE_BYTES - 100);
        // The weight limit is the smaller: four weight units a byte.
        t.weightlimit = weight_used + 4 * 1_000;
        assert_eq!(output_budget(100, &t), 900);
        // The size limit is the smaller.
        t.weightlimit = 4_000_000;
        t.sizelimit = size_used + 500;
        assert_eq!(output_budget(100, &t), 400);
        // No room at all.
        t.sizelimit = size_used;
        assert_eq!(output_budget(100, &t), 0);
    }

    #[test]
    fn the_assembled_coinbase_parses_and_locates_the_pot_byte() {
        let (script, pot_in_script) = script_sig(&tagging(21)).unwrap();
        let wc = [
            0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let outputs = vec![
            CoinbaseOutput { value: 100_000_000, script: ratum::fixtures::p2wpkh(1) },
            CoinbaseOutput { value: 50_000_000, script: ratum::fixtures::p2wpkh(2) },
        ];
        for force in [false, true] {
            let (cb, pot, included) =
                build(&params(&script, pot_in_script, &outputs, Some(&wc), force));
            assert_eq!(included.len(), 2);
            let tx = cb.assemble(&[0u8; 12]);
            assert_eq!(tx[pot], 0xff);
            let parsed = ratum::bitcoin::parse_coinbase(&tx).unwrap();
            assert!(!parsed.has_witness);
            let pushes = ratum::bitcoin::script_pushes(&parsed.script_sig);
            let uid = pushes.iter().find(|(_, d)| d.len() == 7).unwrap();
            assert_eq!(parsed.script_sig_offset + uid.0, pot);
            let total: u64 = parsed.outputs.iter().map(|o| o.value).sum();
            assert_eq!(total, 312_500_000);
            assert_eq!(parsed.outputs.len(), if force { 5 } else { 4 });
            if force {
                assert_eq!(parsed.outputs[0].value, 0);
                assert_eq!(parsed.outputs[0].script.len(), 16);
                assert_eq!(parsed.outputs[0].script[0], 0x6a);
            }
            assert_eq!(parsed.outputs.last().unwrap().script, wc.to_vec());
            assert_eq!(
                parsed.script_sig.len(),
                if force { script.len() } else { script.len() + 15 }
            );
        }
    }

    #[test]
    fn the_wide_prime_push_takes_four_bytes_from_the_tags_and_stays_within_100() {
        // Short tags are not trimmed, so the version 3 script is exactly the 4 extra prime
        // bytes longer than the version 1 one.
        let v1 = script_sig(&tagging(21)).unwrap().0;
        let mut t = tagging(21);
        t.wide_prime = true;
        let v3 = script_sig(&t).unwrap().0;
        assert_eq!(v3.len(), v1.len() + 4);
        assert_eq!(ratum::bitcoin::script_pushes(&v3).last().unwrap().1.len(), 11);

        // Tags that fill the version 1 budget are trimmed by 4 under version 3, so the
        // scriptSig never exceeds the consensus limit of 100 bytes.
        let mut t = tagging(21);
        t.tag_primary = "RATUM is a pool for the Bitcoin Knots BLAKE2b hardfork";
        t.tag_secondary = "a secondary tag of some length";
        let v1 = script_sig(&t).unwrap().0;
        t.wide_prime = true;
        let v3 = script_sig(&t).unwrap().0;
        assert!(v1.len() <= 100);
        assert!(
            v3.len() <= 100,
            "wide prime push must not push the scriptSig past 100: {}",
            v3.len()
        );
        let tags = |s: &[u8]| ratum::bitcoin::script_pushes(s)[1].1.len();
        assert_eq!(
            tags(&v3) + 4,
            tags(&v1),
            "v3 tag space + 4 != v1 tag space (the u64 prime id push costs 4 bytes)"
        );
    }

    #[test]
    fn a_long_script_sig_moves_the_extranonce_to_an_output() {
        let mut t = tagging(21);
        t.tag_primary = "RATUM is a pool for the Bitcoin Knots BLAKE2b hardfork";
        t.tag_secondary = "a secondary tag of some length";
        let (script, pot) = script_sig(&t).unwrap();
        assert!(script.len() > SCRIPT_SIG_ROOM_FOR_EXTRANONCE);
        assert!(script.len() <= 100);
        let (cb, _, _) = build(&params(&script, pot, &[], None, false));
        let tx = cb.assemble(&[0u8; 12]);
        let parsed = ratum::bitcoin::parse_coinbase(&tx).unwrap();
        assert_eq!(parsed.outputs.len(), 2);
        assert_eq!(parsed.outputs[0].script[0], 0x6a);
    }

    #[test]
    fn outputs_over_the_value_or_budget_are_left_out() {
        let (script, pot) = script_sig(&tagging(21)).unwrap();
        let outputs = vec![
            CoinbaseOutput { value: 300_000_000, script: ratum::fixtures::p2wpkh(1) },
            CoinbaseOutput { value: 50_000_000, script: ratum::fixtures::p2wpkh(2) },
            CoinbaseOutput { value: 10_000_000, script: ratum::fixtures::p2wpkh(3) },
        ];
        let mut p = params(&script, pot, &outputs, None, false);
        p.output_budget = 31 + 31 + 20;
        let (cb, _, included) = build(&p);
        assert_eq!(included.len(), 2);
        assert_eq!(included[1].value, 10_000_000);
        let parsed = ratum::bitcoin::parse_coinbase(&cb.assemble(&[0u8; 12])).unwrap();
        assert_eq!(parsed.outputs[2].value, 2_500_000);
    }
}
