//! Every decoder against random and damaged input. Each message type is encoded, then a byte is
//! flipped or the message is cut, and the decoder must either refuse it or decode it into
//! something whose encoding is a fixed point: decoding those bytes again and re-encoding gives
//! the same bytes. The re-encoding need not equal the damaged input, since a decoder may read a
//! damaged message as a shorter or different valid one. A decoder with no encoder must refuse
//! or decode each damaged input. No input may panic.

use ratum::bitcoin;
use ratum::bitcoin::transaction::CoinbaseTx;
use ratum::datum::bulk::Fragment;
use ratum::datum::client::ClientChannel;
use ratum::datum::coinbase::{self, ScriptSigInputs};
use ratum::datum::framing::{self, FrameHeader, HeaderKeyRatchet};
use ratum::datum::handshake::{ProtocolVersion, RESUME_TOKEN_LEN};
use ratum::datum::keys::KeyPairs;
use ratum::datum::messages::abw::{self, AssignmentNotice, CandidateRef, Reveal};
use ratum::datum::messages::coinbaser::{CoinbaserRequest, CoinbaserResponse};
use ratum::datum::messages::config::ClientConfig;
use ratum::datum::messages::migration::MigrationRequest;
use ratum::datum::messages::share::{Blake2bSection, CoinbaseSection, JobSection, PowSubmit};
use ratum::datum::messages::share_response::{RejectReason, ShareResponse, ShareVerdict};
use ratum::datum::messages::validation::{self, TxnList, TxnListStatus};
use ratum::datum::server;
use ratum::header::{self, BlockHeaderV2};
use ratum::target;
use std::sync::OnceLock;

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

/// The pool key pair every hello below is sealed to, generated once.
fn pool_keys() -> &'static KeyPairs {
    static KEYS: OnceLock<KeyPairs> = OnceLock::new();
    KEYS.get_or_init(KeyPairs::generate)
}

/// The length of the masked header before every frame's body.
const FRAME_HEADER_LEN: usize = 4;

/// The header a hello arrives under: signed, sealed to the pool's key, command 1.
fn hello_header(cmd_len: usize) -> FrameHeader {
    FrameHeader {
        cmd_len: cmd_len as u32,
        is_signed: true,
        is_encrypted_pubkey: true,
        proto_cmd: framing::cmd::HELLO_OR_PING,
        ..Default::default()
    }
}

/// Where `coinbase_with_script_sig` places the scriptSig in the transaction.
const SCRIPT_SIG_OFFSET: usize = 42;

/// A coinbase whose scriptSig is `script_sig`, as `parse_coinbase` would return it.
fn coinbase_with_script_sig(script_sig: &[u8]) -> CoinbaseTx {
    CoinbaseTx {
        version: 1,
        script_sig_offset: SCRIPT_SIG_OFFSET,
        script_sig: script_sig.to_vec(),
        sequence: u32::MAX,
        outputs: Vec::new(),
        lock_time: 0,
        has_witness: false,
    }
}

fn feed_everything(blob: &[u8]) {
    let _ = PowSubmit::decode(blob);
    let _ = ClientConfig::decode(blob);
    let _ = CoinbaserRequest::decode(blob);
    let _ = CoinbaserResponse::decode(blob);
    let _ = ShareResponse::decode(blob);
    let _ = TxnList::decode(blob, validation::response::TXNS);
    let _ = TxnList::decode(blob, validation::response::BLOCK_TXNS);
    let _ = AssignmentNotice::decode(blob);
    for selector in [abw::subcmd::CANDIDATE_RECEIPT, abw::subcmd::CANDIDATE_RELEASE] {
        let _ = CandidateRef::decode_candidate(blob, selector);
    }
    let _ = Reveal::decode(blob);
    let _ = MigrationRequest::decode(blob);
    let _ = Fragment::decode(blob);
    let _ = server::open_hello(hello_header(blob.len()), blob, pool_keys());
    let tx = coinbase_with_script_sig(blob);
    for prime_id in [0, 1, 0xdead_beef, u64::MAX] {
        for tag in ["", "RATUM"] {
            let _ = coinbase::parse_script_sig(&tx, prime_id, tag);
        }
    }
    let _ = BlockHeaderV2::deserialize(blob);
    let _ = bitcoin::transaction::parse_coinbase(blob);
    let _ = bitcoin::transaction::txid(blob);
    let _ = bitcoin::script::script_pushes(blob);
    let _ = bitcoin::address::output_script_to_display(blob);
    let text = String::from_utf8_lossy(blob);
    for chain in [None, Some(bitcoin::address::MAIN)] {
        let _ = bitcoin::address::to_output_script(&text, chain);
    }
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
    let selectors: [u8; 16] = [
        0x27, 0x99, 0x10, 0x11, 0x8f, 0x50, 0x90, 0x91, 0x92, 0xfe, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
        0xa9,
    ];
    let mut rng = Rng::new(0xABCD_EF01_2345_6789);
    for _ in 0..4_000 {
        let pick = rng.below(selectors.len());
        let mut blob = if rng.below(8) == 0 { b"DBF\x01".to_vec() } else { Vec::new() };
        blob.push(selectors[pick]);
        if rng.bool() {
            let pick = rng.below(selectors.len());
            blob.push(selectors[pick]);
        }
        let tail = rng.below(300);
        blob.extend(rng.bytes(tail));
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

/// Every prefix of `valid`, 2000 single bit flips at random positions, and every byte replaced
/// by each of a few boundary values, each with what was done to it.
fn damaged(valid: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let mut out: Vec<(&'static str, Vec<u8>)> =
        (0..valid.len()).map(|cut| ("a prefix", valid[..cut].to_vec())).collect();
    let mut rng = Rng::new(0x1122_3344_5566_7788);
    for _ in 0..2_000 {
        let mut flipped = valid.to_vec();
        let at = rng.below(flipped.len());
        flipped[at] ^= 1 << rng.below(8);
        out.push(("a bit flip", flipped));
    }
    for at in 0..valid.len() {
        for byte in [0x00u8, 0x01, 0x7f, 0x80, 0xfd, 0xfe, 0xff] {
            let mut replaced = valid.to_vec();
            replaced[at] = byte;
            out.push(("a replaced byte", replaced));
        }
    }
    out
}

/// `valid` must decode and re-encode to itself; every damaged form of it must be refused or
/// decode to a message whose encoding is a fixed point of decoding and re-encoding.
fn truncations_and_flips(valid: &[u8], decode_encode: impl Fn(&[u8]) -> Option<Vec<u8>>) {
    assert_eq!(
        decode_encode(valid).as_deref(),
        Some(valid),
        "the undamaged message must re-encode to itself"
    );
    for (what, bytes) in damaged(valid) {
        if let Some(re) = decode_encode(&bytes) {
            assert_eq!(
                decode_encode(&re).as_deref(),
                Some(re.as_slice()),
                "{what}: the re-encoding is not a fixed point"
            );
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
        extranonce: rng.bytes(12).try_into().unwrap(),
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
        abw_slot: rng.bool().then(|| rng.byte() & 0x0f),
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
        v3: None,
    };
    let valid = config.encode().unwrap();
    truncations_and_flips(&valid, |bytes| {
        ClientConfig::decode(bytes).ok().and_then(|c| c.encode().ok())
    });
}

#[test]
fn a_damaged_coinbaser_response_is_refused_or_reproduces_itself() {
    let response = CoinbaserResponse {
        value: 312_500_000,
        coinbaser_id: 9,
        outputs: (0..6)
            .map(|i| bitcoin::transaction::TxOut {
                value: 1_000_000 + i,
                script_pubkey: vec![0x00, 0x14, i as u8],
            })
            .collect(),
    };
    let valid = response.encode().unwrap();
    truncations_and_flips(&valid, |bytes| {
        CoinbaserResponse::decode(bytes).ok().and_then(|r| r.encode().ok())
    });
}

#[test]
fn a_damaged_validation_message_is_refused_or_reproduces_itself() {
    let list = TxnList {
        selector: validation::response::BLOCK_TXNS,
        job_index: 6,
        status: TxnListStatus::Ok,
        txns: vec![vec![0xab; 10], vec![0xcd; 300], vec![]],
    };
    truncations_and_flips(&list.encode(), |bytes| {
        TxnList::decode(bytes, validation::response::BLOCK_TXNS).ok().map(|b| b.encode())
    });
}

#[test]
fn a_damaged_share_response_is_refused_or_reproduces_itself() {
    let response = ShareResponse {
        verdict: ShareVerdict::Rejected(RejectReason::HighHash),
        nonce: 0xdead_beef,
        target_byte: 14,
        job_id: 5,
        abw_ref: None,
    };
    truncations_and_flips(&response.encode(), |bytes| {
        ShareResponse::decode(bytes).ok().map(|r| r.encode())
    });
}

#[test]
fn a_damaged_header_is_refused_or_reproduces_itself() {
    let mut rng = Rng::new(0xFEED_FACE_1234_5678);
    let header = BlockHeaderV2 {
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
        BlockHeaderV2::deserialize(bytes).map(|h| h.serialize().to_vec())
    });
}

#[test]
fn the_version_2_flag_is_not_part_of_the_version() {
    let mut header = BlockHeaderV2 { version: 0x2000_0000, ..Default::default() };
    let serialized = header.serialize();
    assert_eq!(&serialized[..4], &(header::V2_FLAG | 0x2000_0000).to_le_bytes());

    header.version = i32::MIN;
    let round_tripped = BlockHeaderV2::deserialize(&header.serialize()).expect("still a v2 header");
    assert_eq!(round_tripped.version, 0, "the flag bit is stripped, not carried");

    let mut without_flag = BlockHeaderV2::default().serialize();
    without_flag[3] &= 0x7f;
    assert_eq!(BlockHeaderV2::deserialize(&without_flag), None, "the flag bit clear is refused");
}

#[test]
fn hashing_never_panics_on_a_header_that_deserialized() {
    let mut rng = Rng::new(0x2222_3333_4444_5555);
    for _ in 0..300 {
        let mut raw = rng.bytes(header::HEADER_V2_SIZE);
        raw[3] |= 0x80;
        let header = BlockHeaderV2::deserialize(&raw).expect("deserializes");
        let stages = header.hash_stages();
        let asic_input = header.asic_input_with(&stages.work_root, &stages.h2);
        assert_eq!(asic_input.len(), header::ASIC_INPUT_LEN[header.asic_profile() as usize]);
        let hashes = header.pow_hashes();
        assert_eq!(hashes, header.pow_hashes(), "hashing is deterministic");
        assert_eq!(header::blake2b_256(&asic_input), hashes.raw_pow_hash);
        let masked: Vec<u8> =
            hashes.raw_pow_hash.iter().zip(stages.xor_key_mask).map(|(b, m)| b ^ m).collect();
        assert_eq!(masked, hashes.block_hash);
    }
}

#[test]
fn a_coinbase_that_parses_reports_its_script_sig_offset_output_total_and_txid() {
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

        let parsed =
            bitcoin::transaction::parse_coinbase(&tx).expect("a coinbase we built must parse");
        assert_eq!(parsed.script_sig, script);
        assert_eq!(&tx[parsed.script_sig_offset..][..script_len], &script[..]);
        assert_eq!(parsed.outputs.iter().map(|o| o.value).sum::<u64>(), 5_000_000_000);
        assert_eq!(bitcoin::transaction::txid(&tx).expect("txid"), bitcoin::sha256d(&tx));
    }
}

#[test]
fn compact_targets_that_decode_are_within_range() {
    let mut rng = Rng::new(0x4444_5555_6666_7777);
    for _ in 0..20_000 {
        let bits = rng.next() as u32;
        if let Some(target) = target::bits_to_target(bits) {
            assert_eq!(bits & 0x0080_0000, 0, "a negative target must not decode");
            assert!(target.iter().any(|&b| b != 0), "a zero target must not decode: {bits:#010x}");
            let d = target::difficulty_from_bits(bits).expect("a decoded target has a difficulty");
            assert!(d > 0.0 && d.is_finite(), "difficulty {d} for bits {bits:#010x}");
        } else {
            assert_eq!(target::difficulty_from_bits(bits), None, "{bits:#010x}");
        }
    }
    assert!(target::bits_to_target(0x2200_00ff).is_some());
    assert!(target::bits_to_target(0x2300_0001).is_none());
    assert!(target::bits_to_target(0x1d00_0000).is_none(), "a zero mantissa");
}

#[test]
fn a_damaged_assignment_notice_is_refused_or_reproduces_itself() {
    for active in [false, true] {
        let notice = AssignmentNotice { active, slot: 11, key_hash: [0x5a; 32] };
        truncations_and_flips(&notice.encode(), |bytes| {
            AssignmentNotice::decode(bytes).ok().map(|n| n.encode())
        });
    }
}

#[test]
fn a_damaged_candidate_reference_is_refused_or_reproduces_itself() {
    let candidate = CandidateRef { slot: 3, raw_pow_hash_le: [0xc3; 32] };
    for selector in [abw::subcmd::CANDIDATE_RECEIPT, abw::subcmd::CANDIDATE_RELEASE] {
        truncations_and_flips(&candidate.encode_candidate(selector), |bytes| {
            CandidateRef::decode_candidate(bytes, selector)
                .ok()
                .map(|c| c.encode_candidate(selector))
        });
    }
}

#[test]
fn a_damaged_reveal_is_refused_or_reproduces_itself() {
    let reveal = Reveal { slot: 15, xor_key: [0x9e; 16] };
    truncations_and_flips(&reveal.encode(), |bytes| Reveal::decode(bytes).ok().map(|r| r.encode()));
}

#[test]
fn a_damaged_migration_request_is_refused_or_decoded() {
    const HOST: &[u8] = b"pool.example.io";
    let pubkey = KeyPairs::generate().public();
    let mut redirect = vec![0xa4, 0x00, 0x00];
    redirect.extend_from_slice(&(HOST.len() as u16).to_le_bytes());
    redirect.extend_from_slice(HOST);
    redirect.extend_from_slice(&23334u16.to_le_bytes());
    redirect.extend_from_slice(&pubkey.to_bytes());
    redirect.push(0xfe);
    let return_home = [0xa4, 0x00, 0x01, 0xfe];
    match MigrationRequest::decode(&redirect).expect("a redirect we built decodes") {
        MigrationRequest::Redirect(t) => {
            assert_eq!((t.host.as_bytes(), t.port, t.pubkey), (HOST, 23334, pubkey));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(MigrationRequest::decode(&return_home), Ok(MigrationRequest::ReturnHome));
    for valid in [&redirect[..], &return_home[..]] {
        for (_, bytes) in damaged(valid) {
            let _ = MigrationRequest::decode(&bytes);
        }
    }
}

#[test]
fn a_damaged_bulk_fragment_is_refused_or_decoded_within_its_bounds() {
    const HEADER_LEN: usize = 4 + 3 * 4;
    let mut valid = b"DBF\x01".to_vec();
    for field in [7u32, 40_000, 16_384] {
        valid.extend_from_slice(&field.to_le_bytes());
    }
    valid.extend_from_slice(&[0x33; 300]);
    let fragment = Fragment::decode(&valid).expect("a fragment we built decodes");
    assert_eq!((fragment.id, fragment.total_size, fragment.offset), (7, 40_000, 16_384));
    assert_eq!(fragment.data, &[0x33; 300][..]);
    for (what, bytes) in damaged(&valid) {
        if let Ok(f) = Fragment::decode(&bytes) {
            assert!(!f.data.is_empty() && f.data.len() <= 16 * 1024, "{what}");
            assert_eq!(
                f.data,
                &bytes[HEADER_LEN..],
                "{what}: the data is every byte after the header"
            );
        }
    }
}

#[test]
fn a_damaged_hello_is_refused_without_panicking() {
    let pool = pool_keys();
    let mut client = ClientChannel::with_key_pairs(KeyPairs::generate(), KeyPairs::generate(), 77);
    let resume = Some([0x42; RESUME_TOKEN_LEN]);
    let wire = client.hello(&pool.box_pk, "v0.1/decoders", ProtocolVersion::V3 { resume });
    let header = HeaderKeyRatchet::initial().unmask(wire[..FRAME_HEADER_LEN].try_into().unwrap());
    let payload = &wire[FRAME_HEADER_LEN..];
    assert_eq!(header, hello_header(payload.len()));
    let hello = server::open_hello(header, payload, pool).expect("the hello we built opens");
    assert_eq!((hello.user_agent.as_str(), hello.nk), ("v0.1/decoders", 77));
    assert_eq!(hello.protocol_version, ProtocolVersion::V3 { resume });
    for (what, bytes) in damaged(payload).into_iter().filter(|(_, b)| b != payload) {
        assert!(
            server::open_hello(hello_header(bytes.len()), &bytes, pool).is_err(),
            "{what}: a sealed hello altered after sealing must not open"
        );
    }
    for other in [
        FrameHeader { is_signed: false, ..header },
        FrameHeader { is_encrypted_pubkey: false, ..header },
        FrameHeader { is_encrypted_channel: true, ..header },
        FrameHeader { proto_cmd: framing::cmd::MINING, ..header },
    ] {
        assert!(server::open_hello(other, payload, pool).is_err(), "{other:?}");
    }
}

#[test]
fn a_damaged_script_sig_is_refused_or_parsed_without_panicking() {
    let inputs = ScriptSigInputs {
        height: 961_866,
        tag_primary: "RATUM",
        tag_secondary: "garage",
        unique_id: 0x1234,
        prime_id: 0xdead_beef,
        wide_prime: true,
        datum_active: true,
    };
    let (script, target_byte_index) = coinbase::script_sig(&inputs).expect("the tags fit");
    let tx = coinbase_with_script_sig(&script);
    let parsed =
        coinbase::parse_script_sig(&tx, 0xdead_beef, "RATUM").expect("the scriptSig we built");
    assert_eq!(parsed.tag_secondary, "garage");
    assert_eq!(parsed.target_byte_index, SCRIPT_SIG_OFFSET + target_byte_index);
    for (what, bytes) in damaged(&script) {
        let tx = coinbase_with_script_sig(&bytes);
        for (prime_id, tag) in [(0xdead_beef, "RATUM"), (0xdead_beef, ""), (0, "")] {
            if let Some(p) = coinbase::parse_script_sig(&tx, prime_id, tag) {
                let at = p.target_byte_index - SCRIPT_SIG_OFFSET;
                assert!(at < bytes.len(), "{what}: the target byte index is inside the scriptSig");
            }
        }
    }
}
