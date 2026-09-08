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
use ratum::datum::coinbase::{EXTRANONCE_PUSH_SIZE, UID_PUSH_POT_AT, tag_push_data, uid_push};
use ratum::datum::messages::CoinbaseOutput;
use ratum::datum::share::{EXTRANONCE_SIZE, MAX_COINBASE_SECTION_BYTES};

pub const MAX_COINBASE_SCRIPT_SIG: usize = 100;

pub const SCRIPT_SIG_ROOM_FOR_EXTRANONCE: usize = MAX_COINBASE_SCRIPT_SIG - EXTRANONCE_PUSH_SIZE;

const OP_RETURN_EXTRANONCE_OUTPUT_SIZE: usize = MIN_OUTPUT_SIZE + 1 + EXTRANONCE_PUSH_SIZE;

const OP_RETURN_EXTRANONCE_EXTRA_BYTES: usize =
    OP_RETURN_EXTRANONCE_OUTPUT_SIZE - EXTRANONCE_PUSH_SIZE;

fn static_bytes(witness_commitment_len: usize) -> usize {
    const NULL_INPUT: usize = 1 + OUTPOINT_SIZE + 1;
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
    pub wide_prime: bool,
    pub datum_active: bool,
}

pub fn height_push(height: u32) -> Vec<u8> {
    const SIGN_BIT: u8 = 0x80;
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

pub fn script_sig(t: &Tagging<'_>) -> Result<(Vec<u8>, usize), String> {
    let mut script = height_push(t.height);
    script.extend_from_slice(&encode_push(&tag_push_data_that_fits(t)?));
    let prime_id = if t.prime_id == 0 && !t.datum_active {
        &[][..]
    } else if t.wide_prime {
        &t.prime_id.to_le_bytes()[..]
    } else {
        &(t.prime_id as u32).to_le_bytes()[..]
    };
    let pot_index = script.len() + UID_PUSH_POT_AT;
    script.extend_from_slice(&uid_push(t.unique_id, prime_id));
    Ok((script, pot_index))
}

fn tag_push_data_that_fits(t: &Tagging<'_>) -> Result<Vec<u8>, String> {
    let tag0 = t.tag_primary.as_bytes();
    let tag1 = t.tag_secondary.as_bytes();
    let tag_space = crate::config::MAX_COINBASE_TAG_SPACE
        - if t.wide_prime { crate::config::WIDE_PRIME_PUSH_EXTRA_BYTES } else { 0 };
    let mut data = tag_push_data(tag0, tag1);
    if data.len() > tag_space {
        let excess = data.len() - tag_space;
        let kept = if tag1.len() > excess { &tag1[..tag1.len() - excess] } else { &[][..] };
        data = tag_push_data(tag0, kept);
    }
    if data.len() > tag_space {
        return Err("the coinbase tags do not fit".into());
    }
    Ok(data)
}

pub struct Params<'a> {
    pub script_sig: &'a [u8],
    pub pot_index_in_script: usize,
    pub enprefix: u16,
    pub witness_commitment: Option<&'a [u8]>,
    pub pool_script: &'a [u8],
    pub coinbase_value: u64,
    pub outputs: &'a [CoinbaseOutput],
    pub output_budget: usize,
    pub sigop_budget: u64,
    pub force_op_return_extranonce: bool,
}

const COINBASE_TX_VERSION: u32 = 1;
const PRUNABLE_OP_RETURN: [u8; 3] = [OP_RETURN, 0x01, 0x00];

const MIN_USEFUL_OUTPUT_ROOM: usize = 30;

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

    let mut coinb1 = COINBASE_TX_VERSION.to_le_bytes().to_vec();
    coinb1.extend_from_slice(&encode_compact_size(1));
    coinb1.extend_from_slice(&[0u8; HASH_SIZE]);
    coinb1.extend_from_slice(&NULL_OUTPOINT_INDEX);
    let n_out = included.len() as u64 + 1 + u64::from(p.witness_commitment.is_some());
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
        coinb2.extend_from_slice(&encode_output(0, &PRUNABLE_OP_RETURN));
    }
    if let Some(wc) = p.witness_commitment {
        coinb2.extend_from_slice(&encode_output(0, wc));
    }
    coinb2.extend_from_slice(&[0u8; LOCK_TIME_SIZE]);
    (Coinbase { coinb1, coinb2 }, pot_index, included)
}

pub const COINBASE_POOLED: u8 = 1;

pub const MAX_COINBASE_BYTES: usize = MAX_COINBASE_SECTION_BYTES;

pub fn output_budget(fixed_bytes: usize, t: &Template) -> usize {
    let around = (ratum::header::HEADER_V2_SIZE + MAX_TXN_COUNT_SIZE) as u64;
    let size_used = t.totals.size as u64 + around + COINBASE_WITNESS_BYTES;
    let by_size = t.sizelimit.saturating_sub(size_used);
    let weight_used =
        t.totals.weight as u64 + WITNESS_SCALE_FACTOR * around + COINBASE_WITNESS_BYTES;
    let by_weight = t.weightlimit.saturating_sub(weight_used) / WITNESS_SCALE_FACTOR;
    let room = by_size.min(by_weight).min(MAX_COINBASE_BYTES as u64) as usize;
    room.saturating_sub(fixed_bytes)
}

const MAX_TXN_COUNT_SIZE: usize = 5;

const COINBASE_WITNESS_BYTES: u64 = 36;

pub fn output_sigop_cost(script: &[u8]) -> u64 {
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
