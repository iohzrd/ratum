//! What a rebuilt share is checked against: the share and network targets, the time window, the
//! username, and the tip its job builds on.

use super::*;

#[test]
fn accepts_a_share_that_meets_the_share_target() {
    let (mut v, s) = setup();
    let a = v.checked(&s, None, NOW).unwrap();
    assert_eq!(a.difficulty, 1);
    assert!(target::meets_target(&a.block_hash, &target::DIFF1_TARGET));
    assert!(a.is_block);
    let mut again = s.clone();
    again.job = None;
    again.coinbase = None;
    assert_eq!(
        v.checked(&again, None, NOW).map(|r| r.block_hash),
        Ok(a.block_hash),
        "a resend without sections rebuilds the same share; accounting::claim refuses it"
    );
    let mut rolled = again.clone();
    rolled.blake2b.sia_nonce[4] = 1;
    assert_eq!(v.checked(&rolled, None, NOW), Err(RejectReason::HighHash));
}

#[test]
fn a_share_that_misses_the_network_target_is_not_a_block() {
    let (mut v, s) = setup_hard();
    let a = v.checked(&s, None, NOW).unwrap();
    assert!(target::meets_target(&a.block_hash, &target::DIFF1_TARGET));
    assert!(!a.is_block);
}

#[test]
fn the_block_flag_follows_the_mainnet_next_bits() {
    let (mut v, s) = setup_hard();
    v.set_next_bits(Some(0x1a008d4f));
    let a = v.checked(&s, None, NOW).unwrap();
    assert!(!a.is_block, "hash {} is above the 1a008d4f target", hex::encode(a.block_hash));
    let mut v2 = setup_hard().0;
    v2.set_next_bits(Some(0x2100ffff));
    let b = v2.checked(&s, None, NOW).unwrap();
    assert!(b.is_block, "hash {} meets the easy target", hex::encode(b.block_hash));
}

#[test]
fn an_easy_job_target_does_not_make_a_share_a_block() {
    let (mut v, s) = setup();
    v.set_next_bits(Some(0x1b00_ffff));
    v.set_tip(Some([0x5a; 32]), NOW);
    v.set_tip(Some([0x11; 32]), NOW);
    let a = v.checked(&s, None, NOW).unwrap();
    assert!(target::meets_target(&a.block_hash, &target::DIFF1_TARGET));
    assert!(!a.is_block, "the job's easy bits must not make an ordinary share a block");
}

#[test]
fn rejects_a_hash_above_the_share_target() {
    let (mut v, mut s) = setup();
    s.target_byte = 40;
    assert_eq!(v.checked(&s, None, NOW), Err(RejectReason::HighHash));
}

#[test]
fn a_share_cannot_claim_more_difficulty_than_it_was_mined_at() {
    let (mut v, as_mined) = setup();
    let accepted = v.checked(&as_mined, None, NOW).expect("solved at difficulty 1");
    assert_eq!(accepted.difficulty, 1);

    let mut inflated = as_mined.clone();
    inflated.target_byte = 20;
    assert_eq!(inflated.difficulty(), 1 << 20, "what the ledger would have credited");
    assert_eq!(v.checked(&inflated, None, NOW), Err(RejectReason::HighHash));

    let as_mined_cb = v.rebuild_checked_ignoring_target(&as_mined, None, NOW).unwrap().coinbase_tx;
    let inflated_cb = v.rebuild_checked_ignoring_target(&inflated, None, NOW).unwrap().coinbase_tx;
    let differing = as_mined_cb.iter().zip(&inflated_cb).filter(|(a, b)| a != b).count();
    assert_eq!(differing, 1, "exactly the target byte");
}

#[test]
fn a_refused_share_rebuilds_for_the_exact_reference_when_its_job_resolves() {
    let (mut v, share) = setup();
    let mut refused = share.clone();
    refused.username = String::new();
    let refusal = v.verify(&refused, None, NOW).unwrap_err();
    assert_eq!(refusal.reason, RejectReason::BadUsername);
    let rebuilt = refusal.rebuilt.expect("the job section resolves");
    assert_eq!(
        rebuilt.raw_pow_hash,
        v.rebuild_checked_ignoring_target(&share, None, NOW).unwrap().raw_pow_hash
    );
    assert!(
        rebuilt.is_block_candidate(),
        "under the node's regtest target the refused share is a block"
    );

    let (mut v, share) = setup_hard();
    let mut refused = share.clone();
    refused.username = String::new();
    let rebuilt = v.verify(&refused, None, NOW).unwrap_err().rebuilt;
    let rebuilt = rebuilt.expect("the job section resolves");
    assert!(!rebuilt.is_block_candidate(), "under a hard network target it is a share only");

    let mut unknown = share.clone();
    unknown.job = None;
    unknown.job_id = 9;
    let refusal = v.verify(&unknown, None, NOW).unwrap_err();
    assert_eq!(refusal.reason, RejectReason::BadJobId);
    assert!(refusal.rebuilt.is_none(), "an unknown job has no work to rebuild");
}

#[test]
fn a_share_on_a_revealed_slot_is_refused_but_rebuilt_for_its_reference() {
    let (mut v, share) = setup();
    let seeded = [0x11u8; 16];
    let revealed = [0x22u8; 16];
    let mut seeded_slots = [None; ASSIGNMENT_SLOTS as usize];
    seeded_slots[0] = Some(seeded);
    let mut revealed_slots = [None; ASSIGNMENT_SLOTS as usize];
    revealed_slots[1] = Some(revealed);
    let keys = AbwSlotState::with_keys(seeded_slots, revealed_slots);

    let mut on_seeded = share.clone();
    on_seeded.abw_slot = Some(0);
    assert_ne!(v.checked(&on_seeded, Some(&keys), NOW), Err(RejectReason::BadAbwSlot));

    let mut on_revealed = share.clone();
    on_revealed.abw_slot = Some(1);
    let refusal = v.verify(&on_revealed, Some(&keys), NOW).unwrap_err();
    assert_eq!(refusal.reason, RejectReason::BadAbwSlot);
    let rebuilt = refusal.rebuilt.expect("rebuilt with the revealed key");
    assert_eq!(&rebuilt.header[112..128], &revealed, "the header carries the revealed key");

    let mut never_seeded = share.clone();
    never_seeded.abw_slot = Some(2);
    assert_eq!(
        v.verify(&never_seeded, Some(&keys), NOW).unwrap_err(),
        Refusal::unreferenced(RejectReason::BadAbwSlot)
    );

    let mut without = share;
    without.abw_slot = None;
    assert_eq!(
        v.verify(&without, Some(&keys), NOW).unwrap_err(),
        Refusal::unreferenced(RejectReason::BadAbwSlot)
    );
}

#[test]
fn a_share_meeting_its_jobs_own_bits_is_a_block_candidate_without_being_a_block() {
    let (mut v, s) = setup();
    let job = s.job.clone().unwrap();
    v.set_next_bits(Some(0x1b00_ffff));
    v.set_tip(Some(job.prev_hash), NOW);
    let refusal = v.verify(&s, None, NOW).unwrap_err();
    assert_eq!(refusal.reason, RejectReason::BadTarget);
    let rebuilt = refusal.rebuilt.expect("rebuilt before the on-tip bits check");
    assert_eq!(rebuilt.job_bits, u32::from_le_bytes(NBITS));
    assert!(meets_own_bits(&rebuilt));
    assert!(rebuilt.is_block_candidate(), "a block by the job's own bits gets the receipt");

    let (mut v, s) = setup();
    v.set_next_bits(Some(0x1b00_ffff));
    v.set_tip(Some([0x5a; 32]), NOW);
    v.set_tip(Some([0x11; 32]), NOW);
    let a = v.checked(&s, None, NOW).unwrap();
    assert!(!a.is_block, "the node's target is not met, so it is not relayed");
    assert!(a.is_block_candidate(), "the gateway's audit counts it as a block");

    let (mut v, s) = setup_hard();
    let a = v.checked(&s, None, NOW).unwrap();
    assert!(!meets_own_bits(&a));
    assert!(!a.is_block_candidate());
}

#[test]
fn rejects_an_ntime_outside_the_window() {
    let (mut v, s) = setup();
    let mut old = s.clone();
    old.blake2b.time_on_wire = (NOW - NTIME_WINDOW_SECS - 1) as u32;
    assert_eq!(v.rebuild_checked_ignoring_target(&old, None, NOW), Err(RejectReason::BadNtime));
    let mut ahead = s.clone();
    ahead.blake2b.time_on_wire = (NOW + NTIME_WINDOW_SECS + 1) as u32;
    assert_eq!(v.rebuild_checked_ignoring_target(&ahead, None, NOW), Err(RejectReason::BadNtime));
    let mut stale_field = s.clone();
    stale_field.ntime = (NOW - NTIME_WINDOW_SECS - 1) as u32;
    assert!(
        v.rebuild_checked_ignoring_target(&stale_field, None, NOW).is_ok(),
        "the fixed field is not the block time"
    );
}

#[test]
fn rejects_a_bad_username() {
    let (mut v, s) = setup();
    for name in ["", "has space", "tab\there", ".", ".rig"] {
        let mut bad = s.clone();
        bad.username = name.to_string();
        assert_eq!(v.checked(&bad, None, NOW), Err(RejectReason::BadUsername), "{name:?}");
    }
}

#[test]
fn a_time_offset_that_moves_the_block_time_out_of_the_window_is_refused() {
    let (mut v, base) = setup();
    let mut s = base.clone();
    s.blake2b.sia_ntime[..4].copy_from_slice(&(NTIME_WINDOW_SECS as u32 + 10).to_le_bytes());
    s.use_time_offset = true;
    assert_eq!(v.rebuild_checked_ignoring_target(&s, None, NOW), Err(RejectReason::BadNtime));

    let mut ok = s.clone();
    ok.use_time_offset = false;
    assert!(v.rebuild_checked_ignoring_target(&ok, None, NOW).is_ok());
}

#[test]
fn rejects_a_tip_job_that_claims_an_easier_target_than_the_node() {
    let (mut v, s) = setup();
    v.set_tip(Some([0x5a; 32]), NOW);

    v.set_next_bits(Some(0x1d00_ffff));
    assert_eq!(v.rebuild_checked_ignoring_target(&s, None, NOW), Err(RejectReason::BadTarget));

    let mut ok = s.clone();
    let mut job = ok.job.clone().unwrap();
    job.nbits = 0x1d00_ffffu32.to_le_bytes();
    ok.job = Some(job);
    assert!(v.rebuild_checked_ignoring_target(&ok, None, NOW).is_ok());
}

#[test]
fn the_network_target_check_needs_a_tip_match_and_a_template() {
    let (mut v, s) = setup();

    v.set_next_bits(Some(0x1d00_ffff));
    v.set_tip(Some([0x11; 32]), NOW);
    assert!(v.checked(&s, None, NOW).is_ok(), "a job off the tip is not target-checked");

    v.set_tip(Some([0x5a; 32]), NOW);
    v.set_next_bits(None);
    assert!(v.checked(&s, None, NOW).is_ok(), "no template means no target check");
}

fn template(prev_hash: [u8; 32], bits: [u8; 4], height: u32, mintime: u64) -> rpc::TemplateSummary {
    rpc::TemplateSummary {
        prev_hash,
        height,
        coinbase_value: COINBASE_VALUE,
        bits: u32::from_le_bytes(bits),
        mintime,
    }
}

#[test]
fn a_job_on_the_templates_parent_carries_its_bits_height_and_a_time_past_its_mintime() {
    let (mut v, s) = setup();
    let job = s.job.clone().unwrap();
    v.set_template(Some(template(job.prev_hash, NBITS, job.height, NOW - 60)));
    assert!(v.rebuild_checked_ignoring_target(&s, None, NOW).is_ok());

    v.set_template(Some(template(job.prev_hash, HARD_NBITS, job.height, NOW - 60)));
    assert_eq!(
        v.rebuild_checked_ignoring_target(&s, None, NOW),
        Err(RejectReason::BadTarget),
        "bits harder than the template's are refused as well as easier ones"
    );

    v.set_template(Some(template(job.prev_hash, NBITS, job.height + 1, NOW - 60)));
    assert_eq!(
        v.rebuild_checked_ignoring_target(&s, None, NOW),
        Err(RejectReason::HeaderFieldMismatch)
    );

    v.set_template(Some(template(job.prev_hash, NBITS, job.height, NOW + 1)));
    assert_eq!(
        v.rebuild_checked_ignoring_target(&s, None, NOW),
        Err(RejectReason::BadNtime),
        "a time at or before the parent's median time past"
    );

    v.set_template(Some(template([0x11; 32], HARD_NBITS, job.height + 5, NOW + 1)));
    assert!(
        v.rebuild_checked_ignoring_target(&s, None, NOW).is_ok(),
        "a template on another parent says nothing of the job"
    );
}

#[test]
fn a_testnet_job_may_carry_bits_other_than_the_templates() {
    let testnet = SharePolicy { chain: Some(rpc::Chain::Testnet4), ..policy() };
    let (cb, target_byte_index) = coinbase_sections(&testnet, &split().outputs);
    let mut v = Verifier::new(&testnet);
    record(&mut v, &split(), &[], NOW);
    let s = share_on(job_section(target_byte_index), cb);
    let job = s.job.clone().unwrap();
    v.set_template(Some(template(job.prev_hash, HARD_NBITS, job.height, NOW - 60)));
    assert!(
        v.rebuild_checked_ignoring_target(&s, None, NOW).is_ok(),
        "a block far enough past its parent may carry the minimum difficulty there"
    );
}
