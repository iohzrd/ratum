//! Rebuilding a share into the header and hashes the gateway computed, and the fields a rebuild
//! refuses.

use super::*;

#[test]
fn rebuilds_a_correct_share() {
    let (mut v, s) = setup();
    let rebuilt = v.checked(&s, None, NOW).unwrap();
    assert_eq!(rebuilt.difficulty, 1);
    assert_eq!(rebuilt.height, 840_000);
    assert_eq!(rebuilt.paid_to_split, 150_000_000);
    assert_eq!(rebuilt.paid_to_pool, COINBASE_VALUE - 150_000_000);
    assert_eq!(rebuilt.header.len(), ratum::header::HEADER_V2_SIZE);
    let h = built_header(&rebuilt);
    assert_eq!(h.merkle_root, bitcoin::sha256d(&rebuilt.coinbase_tx), "no branches in this job");
    assert_eq!(h.version, 0x2000_0000);
    assert_eq!(h.prev_block, [0x5a; 32]);
    assert_eq!(h.time, s.blake2b.time_on_wire);
    assert_eq!(h.bits, u32::from_le_bytes(NBITS));
    assert_eq!(h.nonce, s.nonce);
    assert_eq!(rebuilt.block_hash, h.pow_hashes().block_hash);
    assert_eq!(
        rebuilt.coinbase_tx[s.job.as_ref().unwrap().target_byte_index as usize],
        s.target_byte
    );
    let n = s.coinbase.as_ref().unwrap().coinb1.len();
    assert_eq!(&rebuilt.coinbase_tx[n..n + share::EXTRANONCE_SIZE], &[0u8; 12]);
    assert_eq!(h.extranonce, share::header_extranonce(&EXTRANONCE));
    assert_eq!(
        ratum::header::work_root(&h.hash_stages().h2, &h.extranonce),
        h.hash_stages().work_root
    );
}

#[test]
fn the_header_is_the_gateways_job_plus_the_miners_nonces() {
    let (mut v, s) = setup();
    let job = s.job.clone().unwrap();
    let rebuilt = v.checked(&s, None, NOW).unwrap();
    let h = built_header(&rebuilt);

    assert_eq!(h.prev_block, job.prev_hash);
    assert_eq!(h.height, job.height as i32);
    assert_eq!(h.bits, u32::from_le_bytes(job.nbits));
    assert_eq!(h.merkle_root, bitcoin::sha256d(&rebuilt.coinbase_tx), "no branches in this job");
    assert_eq!(h.version, 0x2000_0000);
    assert_eq!(h.xor_key, [0u8; 16]);
    assert_eq!(h.mm_rhs, [0u8; 32]);
    assert_eq!(h.xor_key_mask_clear_bits, 0);

    let b = s.blake2b;
    assert_eq!((h.nonce, h.nonce2), b.nonce_fields());
    assert_eq!((h.time_offset, h.nonce3), b.time_fields());
    assert_eq!(
        h.extranonce,
        share::header_extranonce(&s.extranonce),
        "the twelve sent, left-padded into the header field"
    );
    assert_eq!(h.time, b.time_on_wire, "no time offset with flags 0");
}

#[test]
fn the_header_is_always_the_sia_profile() {
    let (mut v, s) = setup();
    let h = built_header(&v.checked(&s, None, NOW).unwrap());
    assert_eq!(h.asic_profile(), 0);
    assert_eq!(h.flags, 0);
    assert_eq!(h.asic_input_with(&h.hash_stages().work_root, &h.hash_stages().h2).len(), 80);
}

#[test]
fn the_time_offset_flag_decides_whether_the_offset_moves_the_block_time() {
    let (mut v, base) = setup();
    let mut s = base.clone();
    s.blake2b.sia_ntime[..4].copy_from_slice(&600u32.to_le_bytes());
    let b = s.blake2b;
    let h = built_header(&v.rebuild_checked_ignoring_target(&s, None, NOW).unwrap());
    assert_eq!(h.time_offset, 600);
    assert_eq!(h.time, b.time_on_wire, "flag clear: the offset is nonce space");

    s.use_time_offset = true;
    let h = built_header(&v.rebuild_checked_ignoring_target(&s, None, NOW).unwrap());
    assert_eq!(h.time, b.time_on_wire + 600, "flag set: the offset is added to the time");
    assert_eq!(h.time_on_wire(), b.time_on_wire, "and the serialized time is unchanged");
}

#[test]
fn the_header_counts_the_coinbase_among_its_transactions() {
    let (mut v, mut s) = setup();
    let job = s.job.clone().unwrap();
    assert_eq!(job.txn_count, 0);
    assert_eq!(
        built_header(&v.rebuild_checked_ignoring_target(&s, None, NOW).unwrap()).txcount,
        1,
        "the coinbase alone"
    );

    let mut with_txns = job.clone();
    with_txns.txn_count = 2;
    s.job = Some(with_txns);
    assert_eq!(
        built_header(&v.rebuild_checked_ignoring_target(&s, None, NOW).unwrap()).txcount,
        3,
        "two plus the coinbase"
    );
}

#[test]
fn a_subsidy_only_header_counts_only_the_coinbase() {
    let p = policy();
    let (mut cb, target_byte_index) = coinbase_sections(&p, &[]);
    cb.coinbase_id = COINBASE_ID_SUBSIDY_ONLY;
    let mut v = Verifier::new(&p);

    let mut job = job_section(target_byte_index);
    job.txn_count = 7;
    job.merkle_branches = vec![[0x42; 32]];

    let s = PowSubmit {
        job_id: 0,
        coinbase_id: COINBASE_ID_SUBSIDY_ONLY,
        is_block: false,
        subsidy_only: true,
        quickdiff: false,
        target_byte: 0,
        ntime: NOW as u32,
        nonce: 0,
        version: header::V2_FLAG | 0x2000_0000,
        extranonce: [0x33; share::EXTRANONCE_SIZE],
        username: "bc1qexample.worker1".to_string(),
        use_time_offset: false,
        job: Some(job),
        coinbase: Some(cb),
        blake2b: section(NOW as u32, 0),
        abw_slot: None,
    };
    let rebuilt = v
        .rebuild_checked_ignoring_target(&s, None, NOW)
        .expect("the job's seven transactions are not carried");
    let h = built_header(&rebuilt);
    assert_eq!(h.txcount, 1, "the coinbase alone, not the job's seven plus one");
    assert_eq!(h.merkle_root, bitcoin::sha256d(&rebuilt.coinbase_tx));
}

#[test]
fn a_quickdiff_share_is_rebuilt_from_its_target_byte() {
    let (mut v, s) = setup();
    let plain = v.checked(&s, None, NOW).unwrap();
    let mut quick = s.clone();
    quick.quickdiff = true;
    let with_quickdiff = v.checked(&quick, None, NOW).unwrap();
    assert_eq!(with_quickdiff.coinbase_tx, plain.coinbase_tx);
    assert_eq!(with_quickdiff.block_hash, plain.block_hash);
}

#[test]
fn shares_round_trip_through_encode_and_decode() {
    let (_, s) = setup();
    let bytes = s.encode();
    assert_eq!(bytes[17], share::EXTRANONCE_SIZE as u8);
    assert_eq!(PowSubmit::decode(&bytes).unwrap(), s);
}

#[test]
fn hashes_merkle_branches_into_the_root() {
    let (mut v, mut s) = setup();
    let mut job = s.job.clone().unwrap();
    job.merkle_branches = vec![[0x11; 32], [0x22; 32]];
    s.job = Some(job.clone());
    let rebuilt = v.rebuild_checked_ignoring_target(&s, None, NOW).unwrap();
    let expected = bitcoin::merkle_root_from_branches(
        &bitcoin::sha256d(&rebuilt.coinbase_tx),
        &job.merkle_branches,
    );
    let root = built_header(&rebuilt).merkle_root;
    assert_eq!(root, expected);
    assert_ne!(root, bitcoin::sha256d(&rebuilt.coinbase_tx));
}

#[test]
fn a_target_byte_that_is_not_a_difficulty_exponent_is_refused() {
    let (mut v, base) = setup();
    for byte in [0xffu8, 0x80, 64] {
        let mut s = base.clone();
        s.target_byte = byte;
        assert_eq!(v.checked(&s, None, NOW), Err(RejectReason::BadTarget), "byte {byte:#04x}");
    }
}

#[test]
fn rejects_difficulty_below_the_pool_minimum() {
    let mut p = policy();
    p.config.min_difficulty = 16384;
    let (_, s) = setup();
    let mut v = Verifier::new(&p);
    record(&mut v, &split(), &[], NOW);
    assert_eq!(v.rebuild_checked_ignoring_target(&s, None, NOW), Err(RejectReason::BadTarget));
    let mut ok = s.clone();
    ok.target_byte = 14;
    assert!(v.rebuild_checked_ignoring_target(&ok, None, NOW).is_ok());
}

#[test]
fn rejects_a_coinbase_without_the_pool_tag() {
    let mut other = policy();
    other.config.coinbase_tag = "SOMEONEELSE".to_string();
    let (cb, target_byte_index) = coinbase_sections(&other, &split().outputs);
    let mut v = verifier();
    record(&mut v, &split(), &[], NOW);
    let share = share_on(job_section(target_byte_index), cb);
    assert_eq!(v.checked(&share, None, NOW), Err(RejectReason::MissingPoolTag));
}

fn widen_prime_push(
    cb: &CoinbaseSection,
    target_byte_index: usize,
    prime_id: u64,
) -> CoinbaseSection {
    let mut coinb1 = cb.coinb1.clone();
    assert_eq!(
        coinb1[target_byte_index - 1],
        0x07,
        "the 7-byte push opcode precedes the target byte"
    );
    coinb1[target_byte_index - 1] = 0x0b;
    assert_eq!(&coinb1[target_byte_index + 3..target_byte_index + 7], &prime_id.to_le_bytes()[..4]);
    coinb1.splice(
        target_byte_index + 7..target_byte_index + 7,
        prime_id.to_le_bytes()[4..].iter().copied(),
    );
    coinb1[41] += 4;
    CoinbaseSection { coinbase_id: cb.coinbase_id, coinb1, coinb2: cb.coinb2.clone() }
}

#[test]
fn accepts_the_version_3_eleven_byte_prime_push() {
    let mut wide = policy();
    wide.config.prime_id = 0x1122_3344_5566_7788;
    let (cb, target_byte_index) = coinbase_sections(&wide, &split().outputs);
    let cb = widen_prime_push(&cb, target_byte_index, wide.config.prime_id);
    let mut v = Verifier::new(&wide);
    record(&mut v, &split(), &[], NOW);
    let mut share = share_on(job_section(target_byte_index), cb.clone());
    share.target_byte = 5;
    let rebuilt = v
        .rebuild_checked_ignoring_target(&share, None, NOW)
        .expect("the 64-bit prime id is found in the push");
    assert_eq!(
        rebuilt.coinbase_tx[target_byte_index], 5,
        "the target byte is at the claimed index"
    );

    let (narrow, _) = coinbase_sections(&wide, &split().outputs);
    share.coinbase = Some(narrow);
    assert_eq!(
        v.rebuild_checked_ignoring_target(&share, None, NOW),
        Err(RejectReason::MissingPoolTag)
    );
    let mut other = verifier();
    record(&mut other, &split(), &[], NOW);
    share.coinbase = Some(cb);
    assert_eq!(
        other.rebuild_checked_ignoring_target(&share, None, NOW),
        Err(RejectReason::MissingPoolTag)
    );
}

#[test]
fn rejects_a_coinbase_without_the_prime_id() {
    let mut other = policy();
    other.config.prime_id = 0x1234_5678;
    let (cb, target_byte_index) = coinbase_sections(&other, &split().outputs);
    let mut v = verifier();
    record(&mut v, &split(), &[], NOW);
    let share = share_on(job_section(target_byte_index), cb);
    assert_eq!(v.checked(&share, None, NOW), Err(RejectReason::MissingPoolTag));
}

#[test]
fn rejects_a_target_byte_index_pointing_elsewhere() {
    let (mut v, mut s) = setup();
    let mut job = s.job.clone().unwrap();
    job.target_byte_index += 1;
    s.job = Some(job);
    assert_eq!(v.checked(&s, None, NOW), Err(RejectReason::TargetMismatch));
}

#[test]
fn rebuilds_a_subsidy_only_share() {
    let p = policy();
    let (mut cb, target_byte_index) = coinbase_sections(&p, &[]);
    cb.coinbase_id = COINBASE_ID_SUBSIDY_ONLY;
    let mut v = Verifier::new(&p);
    let mut job = job_section(target_byte_index);
    job.merkle_branches = vec![[0x42; 32]];
    let mut share = share_on(job, cb);
    share.subsidy_only = true;
    share.coinbase_id = COINBASE_ID_SUBSIDY_ONLY;

    let rebuilt = v.rebuild_checked_ignoring_target(&share, None, NOW).unwrap();
    assert_eq!(rebuilt.paid_to_split, 0);
    assert_eq!(rebuilt.paid_to_pool, COINBASE_VALUE);
    assert_eq!(built_header(&rebuilt).merkle_root, bitcoin::sha256d(&rebuilt.coinbase_tx));
}

#[test]
fn maps_decode_errors_to_reject_reasons() {
    assert_eq!(
        Verifier::reason_for_decode_error(&messages::Error::BadExtranonceSize(16)),
        RejectReason::BadExtranonceSize
    );
    assert_eq!(
        Verifier::reason_for_decode_error(&messages::Error::Truncated(ratum::reader::Truncated(
            "x"
        ))),
        RejectReason::Other
    );
}

#[test]
fn rejects_a_coinbase_that_is_not_a_transaction() {
    let (mut v, mut s) = setup();
    s.coinbase = Some(CoinbaseSection { coinbase_id: 0, coinb1: vec![0x01, 0x02], coinb2: vec![] });
    assert_eq!(v.checked(&s, None, NOW), Err(RejectReason::BadCoinbase));
}

#[test]
#[ignore = "searches ~2^32 hashes; run with --release -- --ignored to regenerate the nonces"]
fn find_a_difficulty_1_nonce() {
    for (name, (mut v, mut s)) in [("DIFF1_NONCE", setup()), ("DIFF1_NONCE_HARD", setup_hard())] {
        let mut found = false;
        for offset in 0..16u32 {
            s.blake2b.time_on_wire = NOW as u32 + offset;
            s.ntime = s.blake2b.time_on_wire;
            let rebuilt = v.checked(&s, None, NOW + u64::from(offset)).expect("rebuild");
            let h = built_header(&rebuilt);
            let stages = h.hash_stages();
            let input = h.asic_input_with(&stages.work_root, &stages.h2);
            match ratum::nonce::search(
                &input,
                32,
                ratum::header::blake2b_256,
                &target::DIFF1_TARGET,
                || false,
            ) {
                None => println!("{name}: no solution at ntime offset {offset}"),
                Some(nonce) => {
                    println!("{name} = {nonce:#010x}, ntime offset {offset}");
                    found = true;
                    break;
                }
            }
        }
        assert!(found, "no nonce met difficulty 1 for {name}");
    }
}
