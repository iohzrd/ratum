//! The generation transaction, in the layout the C gateway writes and the pool's verifier
//! parses (`datum_coinbaser.c`; `ratum_prime::verify::locate_pot_byte` and `check_outputs`).
//!
//! The transaction is split in two around twelve bytes the assembler inserts (zero in a
//! version 2 job, where the header carries the extranonce instead):
//!
//! ```text
//! coinb1: version, one input with the null outpoint, scriptSig length, scriptSig:
//!           BIP34 height push, tag push (or the headline at the activation height),
//!           uid push (0xFF PoT placeholder, unique id, prime id), PUSH 14, enprefix (2)
//!         [12 bytes]
//! coinb2: sequence, output count, outputs, lock time
//! ```
//!
//! When the scriptSig has no room for the 15-byte extranonce push it goes into a zero-value
//! OP_RETURN output instead, and coinb1 then ends inside that output's script.

use crate::template::Template;
use ratum::bitcoin::{encode_compact_size, encode_output, encode_push};
use ratum::datum::messages::CoinbaseOutput;
use ratum::datum::share::EXTRANONCE_SIZE;

/// The scriptSig length up to which the extranonce push fits inside it (100 - 15).
const SCRIPT_SIG_ROOM_FOR_EXTRANONCE: usize = 85;

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
    pub activation_height: u32,
    pub headline: &'a str,
    pub tag_primary: &'a str,
    pub tag_secondary: &'a str,
    pub unique_id: u16,
    pub prime_id: u32,
    /// Whether a pool dictates the coinbase; with `prime_id` 0 and no pool the uid push is
    /// the short form.
    pub datum_active: bool,
}

/// The BIP34 height push as `CScript() << nHeight`: OP_0, OP_1..OP_16, or a minimal
/// little-endian data push with a zero byte appended when the top bit is set.
pub fn height_push(height: u32) -> Vec<u8> {
    match height {
        0 => vec![0x00],
        1..=16 => vec![0x50 + height as u8],
        h => {
            let mut bytes = Vec::new();
            let mut v = h;
            while v > 0 {
                bytes.push((v & 0xff) as u8);
                v >>= 8;
            }
            if bytes.last().is_some_and(|b| b & 0x80 != 0) {
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
    if t.activation_height > 0 && t.height == t.activation_height && !t.headline.is_empty() {
        if t.headline.len() > crate::config::MAX_COINBASE_TAG_SPACE {
            return Err(format!(
                "the headline is {} bytes; at most {} fit in the coinbase",
                t.headline.len(),
                crate::config::MAX_COINBASE_TAG_SPACE
            ));
        }
        script.extend_from_slice(&encode_push(t.headline.as_bytes()));
    } else {
        let tag0 = t.tag_primary.as_bytes();
        let mut tag1 = t.tag_secondary.as_bytes();
        let mut k = tag0.len() + tag1.len() + 2;
        if tag1.is_empty() {
            k -= 1;
            if tag0.is_empty() {
                k -= 1;
            }
        }
        if k > crate::config::MAX_COINBASE_TAG_SPACE {
            let excess = k - crate::config::MAX_COINBASE_TAG_SPACE;
            if tag1.len() > excess {
                tag1 = &tag1[..tag1.len() - excess];
                k = crate::config::MAX_COINBASE_TAG_SPACE;
            } else if !tag1.is_empty() {
                k -= tag1.len() + 1;
                tag1 = &[];
            }
            if k > crate::config::MAX_COINBASE_TAG_SPACE {
                return Err("the coinbase tags do not fit".into());
            }
        }
        if k > 0 {
            let mut data = Vec::with_capacity(k);
            if !tag0.is_empty() {
                data.extend_from_slice(tag0);
                data.push(if tag1.is_empty() { 0x00 } else { 0x0f });
            } else if !tag1.is_empty() {
                data.push(0x0f);
            }
            if !tag1.is_empty() {
                data.extend_from_slice(tag1);
                data.push(0x00);
            }
            script.extend_from_slice(&encode_push(&data));
        } else {
            script.extend_from_slice(&[0x01, 0x00]);
        }
    }
    let pot_index;
    if t.prime_id == 0 && !t.datum_active {
        script.push(0x03);
        pot_index = script.len();
        script.push(0xff);
        script.extend_from_slice(&t.unique_id.to_le_bytes());
    } else {
        script.push(0x07);
        pot_index = script.len();
        script.push(0xff);
        script.extend_from_slice(&t.unique_id.to_le_bytes());
        script.extend_from_slice(&t.prime_id.to_le_bytes());
    }
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
    pub force_op_return_extranonce: bool,
}

/// Build a coinbase. Returns it, the offset of the PoT byte in the assembled transaction, and
/// the outputs that were included.
pub fn build(p: &Params<'_>) -> (Coinbase, usize, Vec<CoinbaseOutput>) {
    let in_script =
        p.script_sig.len() <= SCRIPT_SIG_ROOM_FOR_EXTRANONCE && !p.force_op_return_extranonce;

    let mut included = Vec::new();
    let mut paid = 0u64;
    let mut remaining = p.output_budget;
    for o in p.outputs {
        if remaining < 30 || paid >= p.coinbase_value {
            break;
        }
        let cost = o.script.len() + 9;
        if paid.saturating_add(o.value) > p.coinbase_value || cost > remaining {
            continue;
        }
        remaining -= cost;
        paid += o.value;
        included.push(o.clone());
    }

    let mut coinb1 = vec![0x01, 0x00, 0x00, 0x00, 0x01];
    coinb1.extend_from_slice(&[0u8; 32]);
    coinb1.extend_from_slice(&[0xff; 4]);
    let n_out = included.len() as u64 + 1 + u64::from(p.witness_commitment.is_some());
    let pot_index;
    let mut coinb2 = Vec::new();
    if in_script {
        coinb1.extend_from_slice(&encode_compact_size(p.script_sig.len() as u64 + 15));
        pot_index = coinb1.len() + p.pot_index_in_script;
        coinb1.extend_from_slice(p.script_sig);
        coinb1.push(0x0e);
        coinb1.extend_from_slice(&p.enprefix.to_be_bytes());
        coinb2.extend_from_slice(&[0xff; 4]);
        coinb2.extend_from_slice(&encode_compact_size(n_out));
    } else {
        coinb1.extend_from_slice(&encode_compact_size(p.script_sig.len() as u64));
        pot_index = coinb1.len() + p.pot_index_in_script;
        coinb1.extend_from_slice(p.script_sig);
        coinb1.extend_from_slice(&[0xff; 4]);
        coinb1.extend_from_slice(&encode_compact_size(n_out + 1));
        coinb1.extend_from_slice(&0u64.to_le_bytes());
        coinb1.push(0x10);
        coinb1.extend_from_slice(&[0x6a, 0x0e]);
        coinb1.extend_from_slice(&p.enprefix.to_be_bytes());
    }
    for o in &included {
        coinb2.extend_from_slice(&encode_output(o.value, &o.script));
    }
    if p.coinbase_value > paid {
        coinb2.extend_from_slice(&encode_output(p.coinbase_value - paid, p.pool_script));
    } else {
        coinb2.extend_from_slice(&encode_output(0, &[0x6a, 0x01, 0x00]));
    }
    if let Some(wc) = p.witness_commitment {
        coinb2.extend_from_slice(&encode_output(0, wc));
    }
    coinb2.extend_from_slice(&[0u8; 4]);
    (Coinbase { coinb1, coinb2 }, pot_index, included)
}

/// The coinbase size classes (`MAX_COINBASE_TYPES`), by the index a stratum job id names.
pub const TYPE_NAMES: [&str; 6] = ["Blank", "Tiny", "Default", "Respect", "Yuge", "Antmain2"];
/// The largest transaction each class may be; 0 is the outputs-free class.
pub const TYPE_MAX_SIZE: [usize; 6] = [0, 500, 755, 6500, 16000, 2250];
pub const TYPE_FORCES_OP_RETURN: [bool; 6] = [false, false, true, false, false, false];
pub const DEFAULT_TYPE: u8 = 2;

/// How many bytes of `max_size` the template leaves for outputs beyond `fixed_bytes`
/// (`datum_stratum_coinbase_fit_to_template`).
pub fn fit_to_template(max_size: usize, fixed_bytes: usize, t: &Template) -> usize {
    let i = fixed_bytes + max_size;
    let mut msz = max_size.saturating_sub(fixed_bytes);
    let size_used = t.totals.size as u64 + 85 + 84 + 36;
    if i as u64 + size_used > t.sizelimit {
        let room = t.sizelimit.saturating_sub(size_used) as usize;
        msz = msz.min(room.saturating_sub(fixed_bytes));
    }
    let weight_used = t.totals.weight as u64 + 340 + 336 + 36;
    if 4 * i as u64 + weight_used > t.weightlimit {
        let room = (t.weightlimit.saturating_sub(weight_used) >> 2) as usize;
        msz = msz.min(room.saturating_sub(fixed_bytes));
    }
    msz
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
            activation_height: 20,
            headline: "Catbus",
            tag_primary: "RATUM",
            tag_secondary: "e2e",
            unique_id: 4242,
            prime_id: 7,
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

        let (s, _) = script_sig(&tagging(20)).unwrap();
        let pushes = ratum::bitcoin::script_pushes(&s);
        assert_eq!(pushes[1].1, b"Catbus");

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
            force_op_return_extranonce: force,
        }
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
