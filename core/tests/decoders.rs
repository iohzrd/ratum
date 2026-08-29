//! Every decoder in the crate, fed what an adversarial or faulty peer would send.
//!
//! Two properties are checked for each one: it never panics, whatever the bytes, and
//! whatever it does accept it reproduces byte for byte when re-encoded. Both matter for a
//! pool that decodes attacker-controlled input on a thread of its own.

use ratum::bitcoin;
use ratum::datum::messages::{
    ClientConfig, CoinbaseOutput, CoinbaserRequest, CoinbaserResponse, RejectReason, ShareResponse,
    ShareVerdict,
};
use ratum::datum::share::{Blake2bSection, CoinbaseSection, JobSection, PowSubmit};
use ratum::datum::validation::{self, ShortTxnList, Status, TxnBundle};
use ratum::header::{self, HeaderV2};
use ratum::target;

/// xorshift64*, so a failure can be reproduced from the seed printed with it.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 24) as u8
    }
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.byte()).collect()
    }
    fn bool(&mut self) -> bool {
        self.next() & 1 == 1
    }
}

/// Run every decoder over one blob. None may panic; each must return.
fn feed_everything(blob: &[u8]) {
    let _ = PowSubmit::decode(blob);
    let _ = ClientConfig::decode(blob);
    let _ = CoinbaserRequest::decode(blob);
    let _ = CoinbaserResponse::decode(blob);
    let _ = ShareResponse::decode(blob);
    let _ = ShortTxnList::decode(blob);
    let _ = TxnBundle::decode(blob, validation::response::TXNS);
    let _ = TxnBundle::decode(blob, validation::response::BLOCK_TXNS);
    let _ = HeaderV2::deserialize(blob);
    let _ = bitcoin::parse_coinbase(blob);
    let _ = bitcoin::txid(blob);
    let _ = bitcoin::script_pushes(blob);
    if blob.len() >= 4 {
        let bits = u32::from_le_bytes(blob[..4].try_into().unwrap());
        let _ = target::bits_to_target(bits);
        let _ = target::difficulty_from_bits(bits);
    }
}

#[test]
fn no_decoder_panics_on_random_bytes() {
    let mut rng = Rng::new(0x5EED_1234_5678_9ABC);
    for round in 0..4_000 {
        let len = match round % 4 {
            0 => rng.below(8),
            1 => rng.below(64),
            2 => rng.below(600),
            _ => rng.below(4096),
        };
        let blob = rng.bytes(len);
        feed_everything(&blob);
    }
}

#[test]
fn no_decoder_panics_on_a_valid_selector_followed_by_random_bytes() {
    // A valid selector, then random bytes. This executes more of each decoder's parse path
    // than uniformly random bytes do.
    let selectors: [u8; 10] = [0x27, 0x99, 0x10, 0x11, 0x8f, 0x50, 0x90, 0x91, 0x92, 0xfe];
    let mut rng = Rng::new(0xABCD_EF01_2345_6789);
    for _ in 0..4_000 {
        let pick = rng.below(selectors.len());
        let mut blob = vec![selectors[pick]];
        if rng.bool() {
            let pick = rng.below(selectors.len());
            blob.push(selectors[pick]);
        }
        let tail = rng.below(300);
        blob.extend(rng.bytes(tail));
        // Lengths near the limits are where a decoder is most likely to read past the end of the
        // input.
        if rng.bool() && blob.len() > 6 {
            let at = 2 + rng.below(blob.len() - 4);
            let pick = rng.below(6);
            let value = [0xff, 0xfe, 0xfd, 0x7f, 0x80, 0x00][pick];
            blob[at] = value;
            blob[at + 1] = value;
        }
        feed_everything(&blob);
    }
}

/// Every prefix of a valid message, and every single-bit change to one, must be either
/// refused or decoded to a value whose encoding is a fixed point.
///
/// Equality with the damaged input is not required (a non-UTF-8 tag returns replacement
/// characters, a non-"ok" validation message carries nothing after the status), but a
/// value must never re-encode to something the decoder then reads differently.
fn truncations_and_flips(valid: &[u8], decode_encode: impl Fn(&[u8]) -> Option<Vec<u8>>) {
    assert_eq!(
        decode_encode(valid).as_deref(),
        Some(valid),
        "the undamaged message must re-encode to itself"
    );
    let stable = |bytes: &[u8], what: &str| {
        if let Some(re) = decode_encode(bytes) {
            assert_eq!(
                decode_encode(&re).as_deref(),
                Some(re.as_slice()),
                "{what}: re-encoding is not stable"
            );
        }
    };

    for cut in 0..valid.len() {
        stable(&valid[..cut], "a prefix");
    }
    let mut rng = Rng::new(0x1122_3344_5566_7788);
    for _ in 0..2_000 {
        let mut damaged = valid.to_vec();
        let at = rng.below(damaged.len());
        damaged[at] ^= 1 << rng.below(8);
        stable(&damaged, "a bit flip");
    }
    for at in 0..valid.len() {
        for byte in [0x00u8, 0x01, 0x7f, 0x80, 0xfd, 0xfe, 0xff] {
            let mut damaged = valid.to_vec();
            damaged[at] = byte;
            stable(&damaged, "a replaced byte");
        }
    }
}

fn random_share(rng: &mut Rng) -> PowSubmit {
    let branches = rng.below(25);
    PowSubmit {
        job_id: rng.byte(),
        coinbase_id: rng.byte(),
        is_block: rng.bool(),
        subsidy_only: rng.bool(),
        quickdiff: rng.bool(),
        target_byte: rng.byte(),
        ntime: rng.next() as u32,
        nonce: rng.next() as u32,
        version: rng.next() as u32,
        extranonce: rng.bytes(12),
        username: format!("bc1q{}.rig{}", rng.below(1_000_000), rng.below(100)),
        job: rng.bool().then(|| JobSection {
            prev_hash: rng.bytes(32).try_into().unwrap(),
            target_byte_index: rng.next() as u16,
            nbits: rng.bytes(4).try_into().unwrap(),
            coinbaser_id: rng.byte(),
            height: rng.next() as u32,
            coinbase_value: rng.next(),
            txn_count: rng.next() as u32,
            txn_total_weight: rng.next() as u32,
            txn_total_size: rng.next() as u32,
            txn_total_sigops: rng.next() as u32,
            merkle_branches: (0..branches).map(|_| rng.bytes(32).try_into().unwrap()).collect(),
        }),
        coinbase: {
            let (n1, n2, want) = (rng.below(300), rng.below(300), rng.bool());
            want.then(|| CoinbaseSection {
                coinbase_id: rng.byte(),
                coinb1: rng.bytes(n1),
                coinb2: rng.bytes(n2),
            })
        },
        use_time_offset: rng.byte() & 1 == 1,
        blake2b: Blake2bSection {
            sia_ntime: rng.bytes(8).try_into().unwrap(),
            sia_nonce: rng.bytes(8).try_into().unwrap(),
            time_on_wire: rng.next() as u32,
        },
    }
}

#[test]
fn shares_round_trip_whatever_their_fields() {
    let mut rng = Rng::new(0xDEAD_BEEF_CAFE_F00D);
    for _ in 0..500 {
        let mut share = random_share(&mut rng);
        if let Some(cb) = &mut share.coinbase {
            cb.coinbase_id = share.coinbase_id;
        }
        let bytes = share.encode();
        let back = PowSubmit::decode(&bytes).expect("a share we built must decode");
        assert_eq!(back, share);
        assert_eq!(back.encode(), bytes);
    }
}

#[test]
fn a_share_carries_its_blake2b_section_intact() {
    let mut rng = Rng::new(0x0102_0304_0506_0708);
    for _ in 0..200 {
        let mut share = random_share(&mut rng);
        if let Some(cb) = &mut share.coinbase {
            cb.coinbase_id = share.coinbase_id;
        }
        let bytes = share.encode();
        let back = PowSubmit::decode(&bytes).expect("a share must decode");
        assert_eq!(back.blake2b, share.blake2b);
    }
}

#[test]
fn a_damaged_share_is_refused_or_reproduces_itself() {
    let mut rng = Rng::new(7);
    let mut share = random_share(&mut rng);
    share.coinbase = Some(CoinbaseSection {
        coinbase_id: share.coinbase_id,
        coinb1: vec![0xab; 90],
        coinb2: vec![0xcd; 40],
    });
    let valid = share.encode();
    truncations_and_flips(&valid, |bytes| PowSubmit::decode(bytes).ok().map(|s| s.encode()));
}

#[test]
fn a_damaged_config_is_refused_or_reproduces_itself() {
    let config = ClientConfig {
        payout_script: vec![0x00, 0x14, 0xab, 0xcd, 0xef, 0x01],
        prime_id: 0xdead_beef,
        coinbase_tag: "RATUM".to_string(),
        min_difficulty: 16384,
    };
    let valid = config.encode().unwrap();
    truncations_and_flips(&valid, |bytes| {
        ClientConfig::decode(bytes).and_then(|c| c.encode().ok())
    });
}

#[test]
fn a_damaged_coinbaser_response_is_refused_or_reproduces_itself() {
    let response = CoinbaserResponse {
        value: 312_500_000,
        coinbaser_id: 9,
        outputs: (0..6)
            .map(|i| CoinbaseOutput { value: 1_000_000 + i, script: vec![0x00, 0x14, i as u8] })
            .collect(),
    };
    let valid = response.encode().unwrap();
    truncations_and_flips(&valid, |bytes| {
        CoinbaserResponse::decode(bytes).and_then(|r| r.encode().ok())
    });
}

#[test]
fn a_damaged_validation_message_is_refused_or_reproduces_itself() {
    let list = ShortTxnList {
        job_index: 4,
        status: Status::Ok,
        txn_count: 3,
        short_ids: vec![1, 2, 3],
        crosscheck: Some([0x5a; 32]),
    };
    truncations_and_flips(&list.encode(), |bytes| {
        ShortTxnList::decode(bytes).ok().map(|l| l.encode())
    });

    let bundle = TxnBundle {
        selector: validation::response::BLOCK_TXNS,
        job_index: 6,
        status: Status::Ok,
        txns: vec![vec![0xab; 10], vec![0xcd; 300], vec![]],
    };
    truncations_and_flips(&bundle.encode(), |bytes| {
        TxnBundle::decode(bytes, validation::response::BLOCK_TXNS).ok().map(|b| b.encode())
    });
}

#[test]
fn a_damaged_share_response_is_refused_or_reproduces_itself() {
    let response = ShareResponse {
        verdict: ShareVerdict::Rejected(RejectReason::HighHash),
        nonce: 0xdead_beef,
        target_byte: 14,
        job_id: 5,
    };
    truncations_and_flips(&response.encode(), |bytes| {
        ShareResponse::decode(bytes).map(|r| r.encode())
    });
}

#[test]
fn a_damaged_header_is_refused_or_reproduces_itself() {
    let mut rng = Rng::new(0xFEED_FACE_1234_5678);
    let header = HeaderV2 {
        version: 0x2000_0004,
        prev_block: rng.bytes(32).try_into().unwrap(),
        merkle_root: rng.bytes(32).try_into().unwrap(),
        time: 1_760_000_000,
        bits: 0x1d00_ffff,
        nonce: 0x1234_5678,
        nonce2: 0x9abc_def0,
        nonce3: 0x0f1e_2d3c,
        extranonce: rng.bytes(16).try_into().unwrap(),
        time_offset: 42,
        txcount: 2100,
        flags: 4,
        xor_key_mask_clear_bits: 24,
        xor_key: rng.bytes(16).try_into().unwrap(),
        height: 840_000,
        mm_rhs: rng.bytes(32).try_into().unwrap(),
    };
    truncations_and_flips(&header.serialize(), |bytes| {
        HeaderV2::deserialize(bytes).map(|h| h.serialize().to_vec())
    });
}

#[test]
fn the_version_2_flag_is_not_part_of_the_version() {
    let mut header = HeaderV2 { version: 0x2000_0000, ..Default::default() };
    let serialized = header.serialize();
    assert_eq!(&serialized[..4], &(header::V2_FLAG | 0x2000_0000).to_le_bytes());

    header.version = i32::MIN; // the flag bit, set in the version itself
    let round_tripped = HeaderV2::deserialize(&header.serialize()).expect("still a v2 header");
    assert_eq!(round_tripped.version, 0, "the flag bit is stripped, not carried");

    let mut without_flag = HeaderV2::default().serialize();
    without_flag[3] &= 0x7f;
    assert_eq!(HeaderV2::deserialize(&without_flag), None, "the flag bit clear is refused");
}

#[test]
fn hashing_never_panics_on_a_header_that_deserialized() {
    let mut rng = Rng::new(0x2222_3333_4444_5555);
    for _ in 0..300 {
        let mut raw = rng.bytes(header::HEADER_V2_SIZE);
        raw[3] |= 0x80; // set the version 2 flag so the header deserializes
        let header = HeaderV2::deserialize(&raw).expect("deserializes");
        let components = header.hash_components();
        assert_eq!(
            components.asic_input.len(),
            header::ASIC_INPUT_LEN[header.asic_profile() as usize]
        );
        assert_eq!(components.result, header.hash_components().result, "hashing is deterministic");
        let mut reversed = header.pow_hash();
        reversed.reverse();
        assert_eq!(reversed, components.result);
    }
}

#[test]
fn a_coinbase_that_parses_reports_its_script_sig_offset_output_total_and_txid() {
    // A coinbase the parser accepts must have its scriptSig at the offset it reports.
    let mut rng = Rng::new(0x9999_8888_7777_6666);
    for _ in 0..200 {
        let script_len = rng.below(100) + 1;
        let mut tx = vec![0x01, 0x00, 0x00, 0x00, 0x01];
        tx.extend_from_slice(&[0u8; 32]);
        tx.extend_from_slice(&[0xff; 4]);
        tx.push(script_len as u8);
        let script = rng.bytes(script_len);
        tx.extend_from_slice(&script);
        tx.extend_from_slice(&[0xff; 4]);
        tx.push(0x01);
        tx.extend_from_slice(&5_000_000_000u64.to_le_bytes());
        tx.push(0x02);
        tx.extend_from_slice(&[0x00, 0x14]);
        tx.extend_from_slice(&[0u8; 4]);

        let parsed = bitcoin::parse_coinbase(&tx).expect("a coinbase we built must parse");
        assert_eq!(parsed.script_sig, script);
        assert_eq!(&tx[parsed.script_sig_offset..][..script_len], &script[..]);
        assert_eq!(parsed.total_output_value(), 5_000_000_000);
        assert_eq!(bitcoin::txid(&tx).expect("txid"), bitcoin::sha256d(&tx));
    }
}

#[test]
fn compact_targets_that_decode_are_within_range() {
    let mut rng = Rng::new(0x4444_5555_6666_7777);
    for _ in 0..20_000 {
        let bits = rng.next() as u32;
        if let Some(target) = target::bits_to_target(bits) {
            assert_eq!(bits & 0x0080_0000, 0, "a negative target must not decode");
            let difficulty = target::difficulty_from_bits(bits);
            if target.iter().any(|&b| b != 0) {
                let d = difficulty.expect("a non-zero target has a difficulty");
                assert!(d > 0.0 && d.is_finite(), "difficulty {d} for bits {bits:#010x}");
            }
        }
    }
    // The exponent bound is exact: 34 is the largest exponent Knots's SetCompact decodes without
    // overflow for this mantissa.
    assert!(target::bits_to_target(0x2200_00ff).is_some());
    assert!(target::bits_to_target(0x2300_0001).is_none());
}
