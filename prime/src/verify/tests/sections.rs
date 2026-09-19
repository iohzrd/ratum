//! The job and coinbase sections a connection installs: when a share may reuse them, when a share
//! installs nothing, and how a new tip evicts the jobs built on an old one.

use super::*;

#[test]
fn later_shares_reuse_the_installed_sections() {
    let (mut v, first) = setup();
    let full = v.checked(&first, None, NOW).unwrap();
    let mut second = first.clone();
    second.job = None;
    second.coinbase = None;
    assert_eq!(v.checked(&second, None, NOW).unwrap(), full);
}

#[test]
fn a_coinbase_section_over_the_limit_installs_nothing() {
    let (mut v, s) = setup();
    let mut big = s.clone();
    big.coinbase = Some(CoinbaseSection {
        coinbase_id: s.coinbase_id,
        coinb1: Vec::new(),
        coinb2: vec![0xcd; MAX_COINBASE_SECTION_LEN + 1],
    });
    assert_eq!(v.checked(&big, None, NOW), Err(RejectReason::CoinbaseTooLarge));
    assert_eq!(v.installed_coinbase_bytes, 0);
    assert!(v.checked(&s, None, NOW).is_ok(), "a section at most the limit installs");
}

#[test]
fn a_share_that_misses_its_target_installs_nothing() {
    let (mut v, mut s) = setup();
    v.set_next_bits(Some(0x1b00_ffff));
    s.blake2b.sia_nonce[0] = s.blake2b.sia_nonce[0].wrapping_add(1);
    assert_eq!(v.checked(&s, None, NOW), Err(RejectReason::HighHash));
    assert!(v.jobs[0].is_none());
    assert_eq!(v.installed_coinbase_bytes, 0);
    let mut bad = s.clone();
    bad.coinbase.as_mut().unwrap().coinb2.push(0);
    assert_eq!(v.checked(&bad, None, NOW), Err(RejectReason::BadCoinbase));
    assert!(v.jobs[0].is_none());
}

#[test]
fn a_block_that_misses_its_share_target_still_installs_its_sections() {
    let (mut v, s) = setup();
    let easy_bits = 0x207f_ffff;
    v.set_next_bits(Some(easy_bits));
    let network = target::bits_to_target(easy_bits).unwrap();
    let mut block = s.clone();
    block.target_byte = 20;
    block.is_block = true;
    let share_target = target::target_for_exponent(block.target_byte);
    let found = (0u32..10_000).any(|nonce| {
        block.nonce = nonce;
        block.blake2b = section(block.ntime, nonce);
        let rebuilt = v.rebuild_checked_ignoring_target(&block, None, NOW).unwrap();
        target::meets_target(&rebuilt.block_hash, &network)
            && !target::meets_target(&rebuilt.block_hash, &share_target)
    });
    assert!(found);
    assert_eq!(v.checked(&block, None, NOW), Err(RejectReason::HighHash));
    assert!(v.jobs[0].is_some(), "the block's sections are installed");
    let mut bare = s.clone();
    bare.job = None;
    bare.coinbase = None;
    assert!(v.checked(&bare, None, NOW).is_ok(), "the next share on the job is served");
}

#[test]
fn a_share_refused_for_its_username_or_time_still_installs_its_sections() {
    let (mut v, s) = setup();
    let mut bad = s.clone();
    bad.username = "bad name".into();
    assert_eq!(v.checked(&bad, None, NOW), Err(RejectReason::BadUsername));
    assert!(v.jobs[0].is_some());
    let mut bare = s.clone();
    bare.job = None;
    bare.coinbase = None;
    assert!(v.checked(&bare, None, NOW).is_ok(), "the next miner's share on the job is served");

    let (mut v, s) = setup();
    let late = NOW + NTIME_WINDOW_SECS + 1;
    assert_eq!(v.checked(&s, None, late), Err(RejectReason::BadNtime));
    assert!(v.checked(&bare, None, NOW).is_ok());
}

#[test]
fn a_first_share_refused_as_stale_still_installs_and_a_block_on_the_job_is_credited() {
    let (mut v, s) = setup_hard();
    v.set_tip(Some([0x5a; 32]), NOW);
    v.set_tip(Some([0x11; 32]), NOW);
    let late = NOW + TIP_GRACE_SECS + 1;
    assert_eq!(v.checked(&s, None, late), Err(RejectReason::StaleBlock));
    assert!(v.jobs[0].is_some(), "the stale share's sections are installed");
    v.set_next_bits(Some(u32::from_le_bytes(NBITS)));
    let mut bare = s.clone();
    bare.job = None;
    bare.coinbase = None;
    assert!(v.checked(&bare, None, late).is_ok(), "a block on the stale job is still credited");
}

#[test]
fn installed_coinbase_sections_are_bounded_per_connection() {
    let (mut v, s) = setup();
    v.set_next_bits(Some(0x1b00_ffff));
    let per_share = coinbase_bytes(s.coinbase.as_ref().unwrap());
    v.installed_coinbase_bytes_cap = 3 * per_share;
    let on_slot = |job_id: u8| PowSubmit { job_id, ..s.clone() };
    // One share installs sections once (`one_share_installs_sections_once`); the fixtures have
    // one solved share, so the record of the shares that installed is cleared between slots.
    let forget_installing_shares =
        |v: &mut Verifier| v.installed_by = crate::bounded::BoundedSet::new(1);
    for job_id in 0..3 {
        forget_installing_shares(&mut v);
        assert!(v.checked(&on_slot(job_id), None, NOW).is_ok());
    }
    forget_installing_shares(&mut v);
    assert_eq!(v.installed_coinbase_bytes, v.installed_coinbase_bytes_cap);
    assert_eq!(v.checked(&on_slot(3), None, NOW), Err(RejectReason::CoinbaseTooLarge));
    assert!(v.jobs[3].is_none(), "a refused share installs neither section");

    let mut replaced = on_slot(0);
    replaced.job.as_mut().unwrap().merkle_branches.push([0; 32]);
    assert_eq!(v.checked(&replaced, None, NOW), Err(RejectReason::HighHash));
    assert!(v.jobs[0].as_ref().is_some_and(|j| j.job == *s.job.as_ref().unwrap()));
    let mut bare = on_slot(0);
    bare.job = None;
    bare.coinbase = None;
    assert!(v.checked(&bare, None, NOW).is_ok(), "the installed sections still serve slot 0");
}

#[test]
fn rejects_a_share_for_an_unknown_job() {
    let (mut v, s) = setup();
    let mut unknown_job = s.clone();
    unknown_job.job = None;
    unknown_job.coinbase = None;
    unknown_job.job_id = 5;
    assert_eq!(v.checked(&unknown_job, None, NOW), Err(RejectReason::BadJobId));
}

#[test]
fn a_repeated_coinbaser_id_cannot_outlive_the_job_naming_it() {
    assert!(MAX_JOBS > usize::from(u8::MAX));
}

#[test]
fn rejects_a_stale_job_once_a_tip_is_known() {
    let (mut v, s) = setup_hard();
    v.set_tip(Some([0x11; 32]), NOW);
    assert_eq!(v.checked(&s, None, NOW), Err(RejectReason::StaleBlock));
    v.set_tip(Some([0x5a; 32]), NOW);
    assert!(v.checked(&s, None, NOW).is_ok());
    v.set_tip(None, NOW);
    assert!(v.checked(&s, None, NOW).is_ok());
}

#[test]
fn a_block_on_a_replaced_tip_is_credited_after_the_grace() {
    let (mut v, s) = setup();
    v.set_tip(Some([0x5a; 32]), NOW);
    v.set_tip(Some([0x11; 32]), NOW);
    assert!(v.checked(&s, None, NOW + 3_600).is_ok(), "the job's tip is still kept");
}

/// A share on a block the node has not reported is stale until the node reports it, block or
/// not, and `parent_unseen` says so, which is what makes the connection hold it rather than
/// answer; the job is kept until its parent is replaced without having been the tip.
#[test]
fn a_job_on_a_tip_the_pool_has_not_seen_is_kept_until_that_tip_is_replaced() {
    for (v, s) in [setup(), setup_hard()] {
        let mut v = v;
        v.set_tip(Some([0x11; 32]), NOW);
        assert_eq!(
            v.checked(&s, None, NOW),
            Err(RejectReason::StaleBlock),
            "0x5a is not a tip yet"
        );
        assert!(v.parent_unseen(&s, [0x5a; 32]), "so the share waits for it");
        assert!(!v.parent_unseen(&s, [0x11; 32]), "the parent named must be the job's");
        v.set_tip(Some([0x22; 32]), NOW);
        v.set_tip(Some([0x33; 32]), NOW + TIP_GRACE_SECS + 1);
        assert_eq!(
            v.checked(&s, None, NOW + TIP_GRACE_SECS + 1),
            Err(RejectReason::StaleBlock),
            "0x5a has never been a tip"
        );
        assert!(v.parent_unseen(&s, [0x5a; 32]), "and the share still waits for it");
        v.set_tip(Some([0x5a; 32]), NOW + TIP_GRACE_SECS + 1);
        assert!(!v.parent_unseen(&s, [0x5a; 32]));
        assert!(v.checked(&s, None, NOW + TIP_GRACE_SECS + 1).is_ok(), "0x5a is the tip");
        v.set_tip(Some([0x44; 32]), NOW + TIP_GRACE_SECS + 1);
        v.set_tip(Some([0x55; 32]), NOW + 2 * TIP_GRACE_SECS + 2);
        assert_eq!(
            v.checked(&s, None, NOW + 2 * TIP_GRACE_SECS + 2),
            Err(RejectReason::StaleBlock)
        );
        assert!(v.jobs[0].as_ref().is_some_and(|j| j.evicted));
        assert!(!v.parent_unseen(&s, [0x5a; 32]), "a replaced parent is not waited for");
    }
}

#[test]
fn nothing_is_installed_into_an_evicted_slot() {
    let (mut v, s) = setup();
    v.set_tip(Some([0x5a; 32]), NOW);
    assert!(v.checked(&s, None, NOW).is_ok());
    for i in 0..=MAX_RECENT_TIPS as u8 {
        v.set_tip(Some([i; 32]), NOW);
    }
    let retained = v.installed_coinbase_bytes;
    assert!(retained > 0, "the evicted job's sections are kept for the refused rebuilds");
    let mut other = s.clone();
    other.coinbase_id = 1;
    other.coinbase.as_mut().unwrap().coinbase_id = 1;
    assert_eq!(v.checked(&other, None, NOW), Err(RejectReason::StaleBlock));
    assert_eq!(v.installed_coinbase_bytes, retained, "nothing more was installed");
}

#[test]
fn a_job_is_evicted_once_its_tip_is_no_longer_kept() {
    let (mut v, s) = setup();
    v.set_tip(Some([0x5a; 32]), NOW);
    assert!(v.checked(&s, None, NOW).is_ok());
    assert!(v.installed_coinbase_bytes > 0);
    for i in 0..=MAX_RECENT_TIPS as u8 {
        v.set_tip(Some([i; 32]), NOW);
    }
    let retained = v.installed_coinbase_bytes;
    assert!(retained > 0, "the sections are kept until a share replaces the job");
    let mut bare = s.clone();
    bare.job = None;
    bare.coinbase = None;
    let refusal = v.verify(&bare, None, NOW).unwrap_err();
    assert_eq!(refusal.reason, RejectReason::StaleBlock);
    let rebuilt = refusal.rebuilt.expect("rebuilt from the evicted job's sections");
    let full = v.verify(&s, None, NOW).unwrap_err();
    assert_eq!(full.reason, RejectReason::StaleBlock);
    assert_eq!(rebuilt.raw_pow_hash, full.rebuilt.unwrap().raw_pow_hash);
    assert!(rebuilt.is_block_candidate());

    let mut over_target = bare.clone();
    over_target.target_byte = ratum::target::MAX_TARGET_EXPONENT + 1;
    assert_eq!(
        v.verify(&over_target, None, NOW).unwrap_err(),
        Refusal::unreferenced(RejectReason::StaleBlock),
        "the eviction is reported ahead of a failed rebuild"
    );
}

#[test]
fn credits_the_job_the_tip_replaced_until_the_grace_ends() {
    let (mut v, s) = setup_hard();
    v.set_tip(Some([0x5a; 32]), NOW);
    v.set_tip(Some([0x11; 32]), NOW);
    assert!(v.checked(&s, None, NOW).is_ok(), "the share that replaced the tip is still credited");
    assert!(v.checked(&s, None, NOW + TIP_GRACE_SECS).is_ok(), "the grace has not ended");
    assert_eq!(
        v.checked(&s, None, NOW + TIP_GRACE_SECS + 1),
        Err(RejectReason::StaleBlock),
        "past the grace the job is stale"
    );
}

#[test]
fn the_grace_outlasts_the_tips_that_follow_it() {
    let (mut v, s) = setup_hard();
    v.set_tip(Some([0x5a; 32]), NOW);
    v.set_tip(Some([0x11; 32]), NOW);
    v.set_tip(Some([0x22; 32]), NOW);
    v.set_tip(Some([0x33; 32]), NOW);
    assert!(v.checked(&s, None, NOW).is_ok(), "0x5a stopped being the tip within TIP_GRACE_SECS");
    assert_eq!(
        v.checked(&s, None, NOW + TIP_GRACE_SECS + 1),
        Err(RejectReason::StaleBlock),
        "age ends the grace, not the number of tips since"
    );
}

#[test]
fn only_a_bounded_number_of_replaced_tips_is_kept() {
    let (mut v, s) = setup_hard();
    v.set_tip(Some([0x5a; 32]), NOW);
    for i in 0..=MAX_RECENT_TIPS as u8 {
        v.set_tip(Some([i; 32]), NOW);
    }
    assert_eq!(
        v.checked(&s, None, NOW),
        Err(RejectReason::StaleBlock),
        "0x5a has been removed from recent_tips"
    );
}

#[test]
fn a_repeated_tip_does_not_restart_the_grace() {
    let (mut v, s) = setup_hard();
    v.set_tip(Some([0x5a; 32]), NOW);
    v.set_tip(Some([0x11; 32]), NOW);
    v.set_tip(Some([0x11; 32]), NOW + TIP_GRACE_SECS);
    assert_eq!(v.checked(&s, None, NOW + TIP_GRACE_SECS + 1), Err(RejectReason::StaleBlock));
}

#[test]
fn rejects_a_coinbase_id_the_share_does_not_claim() {
    let (mut v, s) = setup();
    let mut mismatched = s.clone();
    let mut cb = mismatched.coinbase.clone().unwrap();
    cb.coinbase_id = 3;
    mismatched.coinbase = Some(cb);
    assert_eq!(v.checked(&mismatched, None, NOW), Err(RejectReason::CoinbaseIdMismatch));

    let mut out_of_range = s.clone();
    out_of_range.coinbase_id = MAX_COINBASE_TYPES;
    assert_eq!(v.checked(&out_of_range, None, NOW), Err(RejectReason::BadCoinbaseId));

    let mut wrong_subsidy = s.clone();
    wrong_subsidy.subsidy_only = true;
    assert_eq!(v.checked(&wrong_subsidy, None, NOW), Err(RejectReason::BadCoinbaseId));
}

#[test]
fn rejects_a_share_for_a_coinbase_never_sent() {
    let (mut v, s) = setup();
    let mut no_cb = s.clone();
    no_cb.coinbase = None;
    assert_eq!(v.checked(&no_cb, None, NOW), Err(RejectReason::CoinbaseMissing));
}

#[test]
fn a_resent_job_section_keeps_the_coinbases_already_installed() {
    let (mut v, s) = setup();
    v.checked(&s, None, NOW).unwrap();
    let mut again = s.clone();
    again.coinbase = None;
    assert!(v.checked(&again, None, NOW).is_ok());
}

#[test]
fn one_share_installs_sections_once() {
    let (mut v, s) = setup();
    v.checked(&s, None, NOW).unwrap();
    assert!(v.checked(&s, None, NOW).is_ok(), "the same sections again change nothing");
    let mut elsewhere = s.clone();
    elsewhere.job_id = 7;
    assert_eq!(
        v.checked(&elsewhere, None, NOW),
        Err(RejectReason::DuplicateWork),
        "the same work installing its sections in another slot"
    );
    assert!(v.jobs[7].is_none());
    let mut other_id = s.clone();
    other_id.coinbase_id = 3;
    other_id.coinbase.as_mut().unwrap().coinbase_id = 3;
    assert_eq!(v.checked(&other_id, None, NOW), Err(RejectReason::DuplicateWork));
}

#[test]
fn a_job_whose_parent_the_node_never_reports_is_evicted() {
    let (mut v, s) = setup();
    v.set_tip(Some([0x11; 32]), NOW);
    assert_eq!(v.checked(&s, None, NOW), Err(RejectReason::StaleBlock), "held for its parent");
    let generation = v.installed_generation(&s).expect("installed");
    assert!(v.job(s.job_id, generation).is_some());
    v.set_tip(Some([0x11; 32]), NOW + jobs::UNSEEN_PARENT_SECS);
    assert!(v.job(s.job_id, generation).is_some(), "kept while the parent may still arrive");
    v.set_tip(Some([0x12; 32]), NOW + jobs::UNSEEN_PARENT_SECS + 1);
    assert!(v.job(s.job_id, generation).is_none(), "evicted once it has not in time");
}

#[test]
fn a_connection_holds_the_transactions_of_its_newest_jobs_only() {
    let (mut v, s) = setup();
    let on_slot = |slot: u8| PowSubmit { job_id: slot, ..s.clone() };
    let valid = BlockCheck::Valid { version: 0x2000_0000 };
    for slot in 0..6u8 {
        v.install_sections(&on_slot(slot), [slot; 32], NOW).unwrap();
        let generation = v.installed_generation(&on_slot(slot)).unwrap();
        let none: std::sync::Arc<[std::sync::Arc<[u8]>]> = std::sync::Arc::from(Vec::new());
        assert!(v.set_job_txns(slot, generation, crate::verify::JobTxns::Held(none)));
        v.record_block_check(slot, generation, [slot; 32], valid);
    }
    let holding: Vec<u8> = (0..6u8)
        .filter(|&slot| {
            let generation = v.installed_generation(&on_slot(slot)).unwrap();
            matches!(v.job_txns(slot, generation), Some(crate::verify::JobTxns::Held(_)))
        })
        .collect();
    assert_eq!(holding, vec![2, 3, 4, 5], "the four newest jobs keep theirs");
    let checked: Vec<u8> = (0..6u8)
        .filter(|&slot| {
            let generation = v.installed_generation(&on_slot(slot)).unwrap();
            v.block_check(slot, generation, &[slot; 32]).is_some()
        })
        .collect();
    assert_eq!(
        checked,
        vec![2, 3, 4, 5],
        "a released job's verdicts go with its transactions, so the transactions sent again \
         are validated again"
    );
}
