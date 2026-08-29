//! Fixtures the crate's unit tests and the integration harness share: the coinbase a
//! gateway would build, in the tagging layout the pool's `ratum_prime::verify` checks. The unit tests and
//! the integration tests must use that layout byte for byte, so it is written once here
//! rather than once per test tree. The pool binary does not use this module.

use crate::bitcoin::{encode_compact_size, encode_output, encode_push};
use crate::datum::messages::CoinbaseOutput;
use crate::datum::share::{self, CoinbaseSection};

pub fn p2wpkh(b: u8) -> Vec<u8> {
    let mut s = vec![0x00, 0x14];
    s.extend_from_slice(&[b; 20]);
    s
}

pub fn push(data: &[u8]) -> Vec<u8> {
    encode_push(data)
}

pub fn out(value: u64, script: &[u8]) -> Vec<u8> {
    encode_output(value, script)
}

/// How the coinbase identifies the pool: the tag push the pool searches for, then the 7-byte
/// push whose last four bytes are its prime id. The PoT (power-of-two difficulty) byte is the
/// first byte of that 7-byte push. At the activation height the tag push carries the headline
/// instead.
pub struct Tagging<'a> {
    pub tag: &'a str,
    pub prime_id: u32,
    pub headline: Option<&'a str>,
}

/// A coinbase split in two around the extranonce: it pays `outputs`, then the remainder
/// to `payout_script`, then a zero-value witness commitment. Returns the section and the
/// index of the PoT byte in the assembled transaction.
pub fn coinbase(
    tagging: &Tagging<'_>,
    payout_script: &[u8],
    outputs: &[CoinbaseOutput],
    coinbase_value: u64,
) -> (CoinbaseSection, usize) {
    let mut script = push(&[0x0c, 0xd2, 0x26]);
    match tagging.headline {
        Some(h) => script.extend_from_slice(&push(h.as_bytes())),
        None => {
            let mut tag = tagging.tag.as_bytes().to_vec();
            tag.push(0x00);
            script.extend_from_slice(&push(&tag));
        }
    }
    // The uid push (`generate_coinbase_uid_tag`): the PoT placeholder 0xFF, the 2-byte
    // `coinbase_unique_id` little-endian (0x1234 here; the gateway default is 4242), then the
    // prime id.
    let mut uid = vec![0xff, 0x34, 0x12];
    uid.extend_from_slice(&tagging.prime_id.to_le_bytes());
    script.extend_from_slice(&push(&uid));
    let pot_in_script = script.len() - 7;
    // PUSH 14: the 2-byte enprefix, then the 12-byte extranonce the assembler inserts.
    script.push(0x0e);
    script.extend_from_slice(&[0xab, 0xcd]);

    let mut coinb1 = vec![0x01, 0x00, 0x00, 0x00, 0x01];
    coinb1.extend_from_slice(&[0u8; 32]);
    coinb1.extend_from_slice(&[0xff; 4]);
    coinb1.extend_from_slice(&encode_compact_size((script.len() + share::EXTRANONCE_SIZE) as u64));
    let script_sig_offset = coinb1.len();
    coinb1.extend_from_slice(&script);
    let pot_index = script_sig_offset + pot_in_script;

    let mut coinb2 = vec![0xff, 0xff, 0xff, 0xff];
    let paid: u64 = outputs.iter().map(|o| o.value).sum();
    coinb2.extend_from_slice(&encode_compact_size((outputs.len() + 2) as u64));
    for o in outputs {
        coinb2.extend_from_slice(&out(o.value, &o.script));
    }
    coinb2.extend_from_slice(&out(coinbase_value - paid, payout_script));
    let mut commitment = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    commitment.extend_from_slice(&[0x00; 32]);
    coinb2.extend_from_slice(&out(0, &commitment));
    coinb2.extend_from_slice(&[0u8; 4]);

    (CoinbaseSection { coinbase_id: 0, coinb1, coinb2 }, pot_index)
}
