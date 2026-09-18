//! The share window, the split over it, and the store on disk.

use super::*;
use crate::fixtures::{Scratch, found, hash, payout, share};
use crate::ledger::split::{PublicGateway, PublicGatewayFeeWork, SplitPolicy};

fn work_by_identity(l: &Ledger) -> Vec<(String, u128)> {
    l.identities().into_iter().map(|(id, s)| (id, s.work)).collect()
}

fn identity_work(identity: &str, work: u128) -> (String, u128) {
    (identity.to_string(), work)
}

fn own_work(l: &Ledger) -> HashMap<String, u128> {
    l.identities()
        .into_iter()
        .filter(|(_, s)| s.own_gateway_work != 0)
        .map(|(id, s)| (id, s.own_gateway_work))
        .collect()
}

fn tags_of(l: &Ledger) -> HashMap<String, String> {
    l.identities().into_iter().map(|(id, s)| (id, s.tag_secondary)).collect()
}

fn fixed(window: u128) -> Ledger {
    Ledger::new(WindowRule::fixed(window), SplitPolicy::default())
}

fn ledger_with(window: u128, shares: &[(&str, u64)]) -> Ledger {
    let mut l = fixed(window);
    for (i, (identity, difficulty)) in shares.iter().enumerate() {
        l.record(share(1_000 + i as u64, identity, *difficulty, hash(i as u64), "")).unwrap();
    }
    l
}

#[test]
fn credits_shares_by_identity() {
    let l = ledger_with(1_000_000, &[("alice", 16), ("bob", 32), ("alice", 16)]);
    assert_eq!(l.total_work(), 64);
    assert_eq!(l.len(), 3);
    assert_eq!(work_by_identity(&l), vec![identity_work("alice", 32), identity_work("bob", 32)]);
}

#[test]
fn splits_value_in_proportion_to_work() {
    let l = ledger_with(1_000_000, &[("alice", 75), ("bob", 25)]);
    let split = l.split_value(1_000_000, 0, 512);
    assert_eq!(split, vec![payout("alice", 750_000), payout("bob", 250_000)]);
    assert_eq!(split.iter().map(|p| p.sats).sum::<u64>(), 1_000_000);
}

#[test]
fn no_remainder_is_left_for_the_pool() {
    let l = ledger_with(1_000_000, &[("a", 1), ("b", 1), ("c", 1)]);
    let split = l.split_value(100, 0, 512);
    assert_eq!(split.len(), 3);
    assert_eq!(split.iter().map(|p| p.sats).sum::<u64>(), 100);
}

#[test]
fn the_amounts_always_total_the_value() {
    for value in [1u64, 7, 99, 1_000_003, 3_125_000_000] {
        for works in [
            &[("a", 1u64)][..],
            &[("a", 1), ("b", 2)][..],
            &[("a", 7), ("b", 11), ("c", 13)][..],
            &[("a", 1), ("b", 1), ("c", 1), ("d", 1), ("e", 1), ("f", 1), ("g", 1)][..],
        ] {
            let l = ledger_with(u128::MAX, works);
            let split = l.split_value(value, 0, 512);
            let paid: u64 = split.iter().map(|p| p.sats).sum();
            assert_eq!(paid, value, "value {value} over {} miners", works.len());
        }
    }
}

#[test]
fn amounts_below_the_minimum_are_not_paid() {
    let l = ledger_with(1_000_000, &[("large", 999), ("small", 1)]);
    assert_eq!(l.split_value(1_000_000, 0, 512).len(), 2);

    let split = l.split_value(1_000_000, 10_000, 512);
    assert_eq!(split, vec![payout("large", 1_000_000)]);
}

#[test]
fn dropping_the_smallest_can_raise_the_rest_over_the_minimum() {
    let l = ledger_with(1_000_000, &[("a", 1), ("b", 1), ("c", 1), ("d", 1)]);
    assert_eq!(l.split_value(40_000, 10_000, 512).len(), 4);
    let split = l.split_value(40_000, 10_001, 512);
    assert_eq!(split.len(), 3);
    assert_eq!(split.iter().map(|p| p.sats).sum::<u64>(), 40_000);
    assert!(split.iter().all(|p| p.sats >= 10_001));
}

#[test]
fn a_value_under_the_minimum_pays_nobody() {
    let l = ledger_with(1_000_000, &[("a", 1), ("b", 1)]);
    assert!(l.split_value(9_999, 10_000, 512).is_empty());
}

#[test]
fn output_count_is_capped_largest_first() {
    let l = ledger_with(1_000_000, &[("a", 4), ("b", 3), ("c", 2), ("d", 1)]);
    let split = l.split_value(1_000_000, 0, 2);
    assert_eq!(split.iter().map(|p| p.identity.as_str()).collect::<Vec<_>>(), vec!["a", "b"]);
}

#[test]
fn an_empty_window_pays_nobody() {
    let l = fixed(1_000);
    assert!(l.split_value(5_000_000_000, 0, 512).is_empty());
    assert_eq!(l.total_work(), 0);
    assert!(l.is_empty());
}

#[test]
fn zero_value_or_no_outputs_pays_nobody() {
    let l = ledger_with(1_000, &[("a", 8)]);
    assert!(l.split_value(0, 0, 512).is_empty());
    assert!(l.split_value(1_000_000, 0, 0).is_empty());
}

#[test]
fn the_window_slides_by_work() {
    let mut l = fixed(100);
    for i in 0..10 {
        l.record(share(i, "a", 32, hash(i), "")).unwrap();
    }
    assert!(l.total_work() >= 100, "window holds {} < 100", l.total_work());
    assert!(l.total_work() < 100 + 32, "window holds {}, more than needed", l.total_work());
    assert_eq!(work_by_identity(&l), vec![identity_work("a", l.total_work())]);
}

#[test]
fn a_miner_with_no_recent_shares_is_trimmed_from_the_window() {
    let mut l = fixed(64);
    for i in 0..4 {
        l.record(share(0, "leaver", 16, hash(i), "")).unwrap();
    }
    assert_eq!(l.split_value(1_000, 0, 512), vec![payout("leaver", 1_000)]);
    for i in 0..4 {
        l.record(share(1, "joiner", 16, hash(100 + i), "")).unwrap();
    }
    let split = l.split_value(1_000, 0, 512);
    assert_eq!(split, vec![payout("joiner", 1_000)]);
    assert!(!work_by_identity(&l).iter().any(|(id, _)| id == "leaver"));
}

#[test]
fn a_window_smaller_than_one_share_still_pays_it() {
    let mut l = fixed(1);
    l.record(share(0, "a", 16384, hash(0), "")).unwrap();
    l.record(share(1, "b", 16384, hash(1), "")).unwrap();
    assert_eq!(l.len(), 1);
    assert_eq!(l.split_value(1_000, 0, 512), vec![payout("b", 1_000)]);
}

#[test]
fn large_values_do_not_overflow() {
    let mut l = fixed(u128::MAX);
    l.record(share(0, "a", u64::MAX / 2, hash(0), "")).unwrap();
    l.record(share(1, "b", u64::MAX / 2, hash(1), "")).unwrap();
    let split = l.split_value(2_100_000_000_000_000, 0, 512);
    assert_eq!(split.len(), 2);
    assert_eq!(split[0].sats, 2_100_000_000_000_000 / 2);
}

#[test]
fn a_window_of_u128_max_still_caps_the_share_count() {
    let mut l = fixed(u128::MAX);
    for i in 0..(MAX_SHARES + 50) {
        l.record(share(i as u64, "a", 1, hash(i as u64), "")).unwrap();
    }
    assert_eq!(l.len(), MAX_SHARES);
    assert_eq!(l.total_work(), MAX_SHARES as u128);
    assert_eq!(work_by_identity(&l), vec![identity_work("a", MAX_SHARES as u128)]);
}

#[test]
fn window_tracks_network_difficulty_with_a_floor() {
    let rule = |floor| WindowRule { multiple: 8.0, floor };
    assert_eq!(rule(1).window_for(1_000.0), 8_000);
    assert_eq!(rule(1).window_for(4.6e-10), 1);
    assert_eq!(rule(5_000).window_for(4.6e-10), 5_000);
    assert_eq!(rule(1).window_for(f64::NAN), 1);
    assert_eq!(rule(1).window_for(0.0), 1);
    assert_eq!(rule(100).window_for(1_000.0), 8_000);
    assert_eq!(rule(100_000).window_for(1_000.0), 100_000);
    assert_eq!(WindowRule::fixed(64).window_for(1e30), 64, "a fixed window ignores difficulty");
}

#[test]
fn the_network_difficulty_sizes_the_window_from_the_floor() {
    let mut l = Ledger::new(WindowRule { multiple: 8.0, floor: 16 }, SplitPolicy::default());
    assert_eq!(l.window(), 16, "the floor until a difficulty is set");
    for i in 0..4 {
        l.record(share(i, "a", 16, hash(i), "")).unwrap();
    }
    assert_eq!(l.total_work(), 16);
    assert_eq!(l.set_network_difficulty(4.0), 0, "no store to re-read");
    assert_eq!(l.window(), 32);
    l.record(share(4, "a", 16, hash(4), "")).unwrap();
    assert_eq!(l.total_work(), 32, "the wider window keeps two shares");
}

#[test]
fn the_split_takes_the_operator_fee_and_the_minimum_from_the_policy() {
    let policy = SplitPolicy { fee_bps: 100, min_payout: 10_000, public_gateway: None };
    let mut l = Ledger::new(WindowRule::fixed(u128::MAX), policy);
    for (i, (identity, difficulty)) in [("a", 99u64), ("b", 1)].into_iter().enumerate() {
        l.record(share(i as u64, identity, difficulty, hash(i as u64), "")).unwrap();
    }
    assert_eq!(l.split_policy().fee_on(1_000_000), 10_000);
    assert_eq!(
        l.split(1_000_000),
        vec![payout("a", 990_000)],
        "the 990_000 after the fee is split, and b's 9_900 of it is under the minimum"
    );
}

fn open_file(
    path: &Path,
    window: u128,
    keep: Option<usize>,
    chain: Option<&str>,
) -> io::Result<(Ledger, ReadBack)> {
    let mut l = fixed(window);
    let read_back = l.attach(Store::open(path, keep, chain)?)?;
    Ok((l, read_back))
}

fn open(scratch: &Scratch, window: u128, keep: Option<usize>) -> (Ledger, ReadBack) {
    open_file(&scratch.join("regtest.redb"), window, keep, Some("regtest")).unwrap()
}

#[test]
fn a_new_ledger_is_stamped_with_its_chain() {
    let scratch = Scratch::new("stamp-new");
    let path = scratch.join("main.redb");
    let (l, read_back) = open_file(&path, 1, None, Some("main")).unwrap();
    assert!(!read_back.stamped, "creating a ledger is not adopting one");
    drop(l);
    let (l, again) = open_file(&path, 1, None, Some("main")).unwrap();
    assert!(!again.stamped, "the stamp is already main");
    drop(l);
    assert!(open_file(&path, 1, None, Some("testnet4")).is_err(), "the file is stamped main");
}

#[test]
fn a_ledger_of_another_chain_is_refused() {
    let scratch = Scratch::new("stamp-other");
    let path = scratch.join("shares.redb");
    drop(open_file(&path, 1, None, Some("testnet4")).unwrap());
    let err = open_file(&path, 1, None, Some("main"))
        .err()
        .expect("a ledger of another chain is refused");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    let msg = err.to_string();
    assert!(msg.contains("chain testnet4") && msg.contains("chain main"), "{msg}");
    drop(open_file(&path, 1, None, None).unwrap());
    assert!(
        open_file(&path, 1, None, Some("main")).is_err(),
        "opening without a chain does not clear the stamp"
    );
}

#[test]
fn an_unstamped_ledger_is_adopted_by_the_first_chain_to_open_it() {
    let scratch = Scratch::new("stamp-adopt");
    let path = scratch.join("shares.redb");
    {
        let (mut l, _) = open_file(&path, u128::MAX, None, None).unwrap();
        l.record(share(1, "alice", 16, hash(1), "")).unwrap();
    }
    let (l, read_back) = open_file(&path, u128::MAX, None, Some("testnet4")).unwrap();
    assert!(read_back.stamped);
    assert_eq!(l.len(), 1, "adoption keeps the shares");
    drop(l);
    assert!(open_file(&path, 1, None, Some("main")).is_err());
    assert!(!open_file(&path, 1, None, Some("testnet4")).unwrap().1.stamped);
}

fn public(fee_bps: u16, subsidy_bps: u16) -> PublicGateway {
    PublicGateway { tag: "public".into(), fee_bps, subsidy_bps }
}

fn tagged_ledger(gateway: Option<PublicGateway>, shares: &[(&str, u64, &str)]) -> Ledger {
    let policy = SplitPolicy { public_gateway: gateway, ..SplitPolicy::default() };
    let mut l = Ledger::new(WindowRule::fixed(1_000_000), policy);
    for (i, (identity, difficulty, tag)) in shares.iter().enumerate() {
        l.record(share(1_000 + i as u64, identity, *difficulty, hash(i as u64), tag)).unwrap();
    }
    l
}

const FEE_BPS: u16 = 5_000;
const FULL_SUBSIDY_BPS: u16 = 10_000;

#[test]
fn the_fee_is_charged_on_public_gateway_work_and_reassigned_to_own_gateway_miners() {
    const SHARES: &[(&str, u64, &str)] = &[("alice", 100, "public"), ("bob", 100, "own")];
    let with = |fee_bps, subsidy_bps| tagged_ledger(Some(public(fee_bps, subsidy_bps)), SHARES);

    let l = with(FEE_BPS, FULL_SUBSIDY_BPS);
    assert_eq!(
        l.public_gateway_fee_work(),
        Some(PublicGatewayFeeWork {
            public_gateway_work: 100,
            fee_work: 50,
            reassigned_work: 50,
            own_gateway_work: 100,
        })
    );
    assert_eq!(l.split_value(200, 0, 512), vec![payout("bob", 150), payout("alice", 50)]);

    let half = with(FEE_BPS, 5_000);
    assert_eq!(half.public_gateway_fee_work().unwrap().reassigned_work, 25);
    let split = half.split_value(200, 0, 512);
    assert_eq!(split, vec![payout("bob", 125), payout("alice", 50)]);
    assert_eq!(
        split.iter().map(|p| p.sats).sum::<u64>(),
        175,
        "the fee work not reassigned is left out of the split and reaches the pool as the \
         remainder"
    );

    assert_eq!(
        with(FEE_BPS, 0).split_value(200, 0, 512),
        vec![payout("bob", 100), payout("alice", 50)],
        "with no subsidy the whole fee stays with the pool"
    );

    let untagged = tagged_ledger(None, SHARES);
    assert_eq!(with(0, 0).split_value(200, 0, 512), untagged.split_value(200, 0, 512));
    assert_eq!(untagged.split_value(200, 0, 512), vec![payout("alice", 100), payout("bob", 100)]);
    assert_eq!(untagged.public_gateway_fee_work(), None, "no public gateway, no fee work");
}

/// `split_value` divides by the weights plus the retained fee work, so that total must equal
/// the window's work exactly: any drift between the charge `weights` deducts and the one
/// `public_gateway_fee_work` sums would misallocate the block's value.
#[test]
fn weights_total_the_window() {
    const SHARES: &[(&str, u64, &str)] = &[
        ("alice", 100, "public"),
        ("bob", 100, "own"),
        ("carol", 37, "public"),
        ("dave", 63, ""),
        ("erin", 1, "public"),
    ];
    for fee_bps in [0u16, 1, 250, FEE_BPS, 9_999, 10_000] {
        for subsidy_bps in [0u16, 1, 3_333, FEE_BPS, FULL_SUBSIDY_BPS] {
            for gateway in [None, Some(public(fee_bps, subsidy_bps))] {
                let l = tagged_ledger(gateway, SHARES);
                let (weights, retained) = l.weights();
                let total: u128 = weights.iter().map(|(_, w)| w).sum::<u128>() + retained;
                assert_eq!(
                    total,
                    l.total_work(),
                    "fee {fee_bps} bps, subsidy {subsidy_bps} bps: the weights and the \
                     retained fee work must total the window"
                );
            }
        }
    }
}

#[test]
fn the_subsidy_is_divided_by_own_gateway_work_not_by_all_work() {
    let l = tagged_ledger(
        Some(public(1_000, FULL_SUBSIDY_BPS)),
        &[
            ("alice", 900, "public"),
            ("bob", 300, "own"),
            ("bob", 100, "public"),
            ("carol", 100, "own"),
        ],
    );
    assert_eq!(
        l.public_gateway_fee_work(),
        Some(PublicGatewayFeeWork {
            public_gateway_work: 1_000,
            fee_work: 100,
            reassigned_work: 100,
            own_gateway_work: 400,
        }),
        "bob's public-gateway share is charged and is not own work"
    );
    assert_eq!(
        l.split_value(1_400, 0, 512),
        vec![payout("alice", 810), payout("bob", 465), payout("carol", 125)],
        "the 100 of fee work is divided 75:25 over bob's and carol's own work"
    );
}

#[test]
fn with_no_own_gateway_work_the_fee_stays_with_the_pool() {
    let l = tagged_ledger(Some(public(FEE_BPS, FULL_SUBSIDY_BPS)), &[("alice", 100, "public")]);
    assert_eq!(
        l.public_gateway_fee_work(),
        Some(PublicGatewayFeeWork {
            public_gateway_work: 100,
            fee_work: 50,
            reassigned_work: 0,
            own_gateway_work: 0,
        })
    );
    assert_eq!(
        l.split_value(100, 0, 512),
        vec![payout("alice", 50)],
        "alice is paid her charged work and the 50 reach the pool as the remainder"
    );
}

#[test]
fn own_gateway_work_is_not_charged() {
    let l = tagged_ledger(
        Some(public(FEE_BPS, FULL_SUBSIDY_BPS)),
        &[("bob", 100, "own"), ("carol", 100, "")],
    );
    let work = l.public_gateway_fee_work().unwrap();
    assert_eq!((work.public_gateway_work, work.fee_work), (0, 0));
    assert_eq!(l.split_value(200, 0, 512), vec![payout("bob", 100), payout("carol", 100)]);
}

#[test]
fn own_gateway_work_follows_the_window_and_the_tag() {
    let mut untagged = fixed(64);
    untagged.record(share(1, "alice", 16, hash(1), "public")).unwrap();
    untagged.record(share(2, "bob", 16, hash(2), "own")).unwrap();
    assert!(own_work(&untagged).is_empty(), "no public tag, no own work");

    let policy = SplitPolicy { public_gateway: Some(public(0, 0)), ..SplitPolicy::default() };
    let mut l = Ledger::new(WindowRule::fixed(64), policy);
    l.record(share(1, "alice", 16, hash(1), "public")).unwrap();
    l.record(share(2, "bob", 16, hash(2), "own")).unwrap();
    assert_eq!(own_work(&l), HashMap::from([("bob".to_string(), 16)]));
    assert_eq!(l.split_policy().public_gateway, Some(public(0, 0)));

    l.record(share(3, "bob", 16, hash(3), "")).unwrap();
    assert_eq!(own_work(&l), HashMap::from([("bob".to_string(), 32)]));
    for i in 4..8 {
        l.record(share(i, "carol", 16, hash(i), "own")).unwrap();
    }
    assert_eq!(l.total_work(), 64);
    assert_eq!(
        own_work(&l),
        HashMap::from([("carol".to_string(), 64)]),
        "bob's own work left the window with his shares"
    );
}

#[test]
fn the_fee_is_applied_before_the_output_cap_and_the_minimum() {
    let l = tagged_ledger(
        Some(public(FEE_BPS, FULL_SUBSIDY_BPS)),
        &[("alice", 100, "public"), ("bob", 30, "own"), ("carol", 20, "own")],
    );
    assert_eq!(
        l.split_value(150, 0, 512),
        vec![payout("bob", 60), payout("alice", 50), payout("carol", 40)]
    );
    assert_eq!(
        l.split_value(150, 0, 2),
        vec![payout("bob", 81), payout("alice", 69)],
        "with the subsidy bob outweighs alice for the two outputs and carol is left out"
    );
    assert_eq!(
        l.split_value(150, 45, 512),
        vec![payout("bob", 81), payout("alice", 69)],
        "carol's 40 is under the minimum once the fee is in the weights"
    );
}

#[test]
fn the_tag_is_the_newest_share_of_each_identity_and_leaves_with_it() {
    let mut l = fixed(32);
    l.record(share(1, "alice", 16, hash(1), "old")).unwrap();
    l.record(share(2, "alice", 16, hash(2), "new")).unwrap();
    l.record(share(3, "bob", 16, hash(3), "")).unwrap();
    let tags = tags_of(&l);
    assert_eq!(tags.get("alice").map(String::as_str), Some("new"));
    assert_eq!(tags.get("bob").map(String::as_str), Some(""));
    l.record(share(4, "carol", 16, hash(4), "")).unwrap();
    l.record(share(5, "carol", 16, hash(5), "")).unwrap();
    assert!(!tags_of(&l).contains_key("alice"));
}

#[test]
fn persists_across_a_restart() {
    let scratch = Scratch::new("restart");
    {
        let (mut l, read_back) = open(&scratch, 1_000_000, None);
        assert_eq!(read_back.skipped, 0);
        l.record(share(1, "alice", 32, hash(1), "")).unwrap();
        l.record(share(2, "bob", 16, hash(2), "")).unwrap();
    }
    {
        let (reopened, read_back) = open(&scratch, 1_000_000, None);
        assert_eq!(read_back.skipped, 0);
        assert_eq!(reopened.total_work(), 48);
        assert_eq!(
            work_by_identity(&reopened),
            vec![identity_work("alice", 32), identity_work("bob", 16)]
        );
    }

    {
        let (mut l, _) = open(&scratch, 1_000_000, None);
        l.record(share(3, "alice", 8, hash(3), "")).unwrap();
    }
    let (again, _) = open(&scratch, 1_000_000, None);
    assert_eq!(again.total_work(), 56);
    assert_eq!(again.len(), 3);
}

#[test]
fn hashes_persist_across_a_restart() {
    let scratch = Scratch::new("hashes");
    {
        let (mut l, _) = open(&scratch, 1_000_000, None);
        l.record(share(1, "alice", 16, hash(1), "")).unwrap();
        l.record(share(2, "bob", 32, hash(2), "")).unwrap();
    }
    let (l, _) = open(&scratch, 1_000_000, None);
    assert_eq!(
        l.block_hashes().copied().collect::<Vec<_>>(),
        vec![hash(1), hash(2)],
        "oldest first"
    );
}

#[test]
fn hashes_returns_the_hashes_the_window_holds() {
    let mut l = ledger_with(1_000_000, &[("alice", 16), ("bob", 32)]);
    l.record(share(1_100, "carol", 8, hash(99), "")).unwrap();
    assert_eq!(l.block_hashes().copied().collect::<Vec<_>>(), vec![hash(0), hash(1), hash(99)]);

    let mut narrow = fixed(8);
    narrow.record(share(1, "alice", 8, hash(1), "")).unwrap();
    narrow.record(share(2, "bob", 8, hash(2), "")).unwrap();
    assert_eq!(narrow.block_hashes().copied().collect::<Vec<_>>(), vec![hash(2)]);
}

#[test]
fn read_back_reads_only_as_far_back_as_the_window_needs() {
    let scratch = Scratch::new("read-back-depth");
    {
        let (mut l, _) = open(&scratch, u128::MAX, None);
        for i in 0..1_000u64 {
            l.record(share(i, "miner00", 16, hash(i), "")).unwrap();
        }
    }
    let (l, read_back) = open(&scratch, 160, None);
    assert!(!read_back.truncated);
    assert!(l.total_work() >= 160, "covers the window");
    assert!(l.len() < 100, "without reading the whole store: {} shares", l.len());
    assert_eq!(l.shares.back().unwrap().accepted_at, 999, "and the newest work is in it");
}

#[test]
fn read_back_reports_truncated_when_the_store_holds_less_work_than_the_window() {
    let scratch = Scratch::new("read-back-short");
    {
        let (mut l, _) = open(&scratch, u128::MAX, None);
        for i in 0..5u64 {
            l.record(share(i, "miner00", 16, hash(i), "")).unwrap();
        }
    }
    let (l, read_back) = open(&scratch, 1_000_000, None);
    assert!(read_back.truncated, "the store holds less work than the window requires");
    assert_eq!(l.len(), 5);
}

#[test]
fn narrowing_a_file_less_windows_trim_is_not_undone_by_widening() {
    let mut l = ledger_with(1_000_000, &[("alice", 16), ("bob", 32), ("carol", 8)]);
    assert_eq!(l.total_work(), 56);
    assert_eq!(l.set_window(8), 0);
    assert_eq!(work_by_identity(&l), vec![identity_work("carol", 8)]);
    assert_eq!(l.set_window(1_000_000), 0, "no store to read the trimmed shares back from");
    assert_eq!(l.total_work(), 8, "what was trimmed is gone rather than hidden");
    assert_eq!(l.len(), 1);
}

#[test]
fn widening_the_window_re_reads_shares_from_the_store() {
    let scratch = Scratch::new("widen");
    let (mut l, _) = open(&scratch, 56, None);
    l.record(share(1, "alice", 16, hash(1), "")).unwrap();
    l.record(share(2, "bob", 32, hash(2), "")).unwrap();
    l.record(share(3, "carol", 8, hash(3), "")).unwrap();

    assert_eq!(l.set_window(8), 0);
    assert_eq!(work_by_identity(&l), vec![identity_work("carol", 8)]);
    assert_eq!(l.block_hashes().copied().collect::<Vec<_>>(), vec![hash(3)]);

    assert_eq!(l.set_window(56), 2, "alice and bob are re-read");
    assert_eq!(l.total_work(), 56);
    assert_eq!(
        work_by_identity(&l),
        vec![identity_work("bob", 32), identity_work("alice", 16), identity_work("carol", 8)]
    );
    assert_eq!(l.block_hashes().copied().collect::<Vec<_>>(), vec![hash(1), hash(2), hash(3)]);
}

#[test]
fn dump_returns_every_stored_share_oldest_first() {
    let scratch = Scratch::new("dump");
    let (mut l, _) = open(&scratch, 8, None);
    l.record(share(1, "alice", 16, hash(1), "")).unwrap();
    l.record(share(2, "bob", 16, hash(2), "")).unwrap();
    l.record(share(3, "carol", 16, hash(3), "")).unwrap();
    assert_eq!(l.len(), 1, "the window holds only the newest");
    drop(l);
    let dumped = dump_file(&scratch.join("regtest.redb")).unwrap();
    assert_eq!(dumped.len(), 3, "but the store holds all three");
    assert_eq!(dumped.iter().map(|s| s.accepted_at).collect::<Vec<_>>(), vec![1, 2, 3]);
}

#[test]
fn cumulative_work_survives_a_reopen() {
    let scratch = Scratch::new("cumulative-work");
    {
        let (mut l, _) = open(&scratch, u128::MAX, None);
        l.record(share(1, "alice", 16, hash(1), "")).unwrap();
        l.record(share(2, "bob", 32, hash(2), "")).unwrap();
        assert_eq!(l.cumulative_work(), 48);
    }
    let (mut l, _) = open(&scratch, u128::MAX, None);
    assert_eq!(l.cumulative_work(), 48, "the counter is read back from the store");
    l.record(share(4, "carol", 16, hash(3), "")).unwrap();
    assert_eq!(l.cumulative_work(), 64, "and continues from the stored value");
}

#[test]
fn a_file_less_ledger_counts_cumulative_work_from_its_start() {
    let mut l = fixed(u128::MAX);
    l.record(share(1, "alice", 16, hash(1), "")).unwrap();
    l.record(share(2, "alice", 32, hash(2), "")).unwrap();
    assert_eq!(l.cumulative_work(), 48);
}

#[test]
fn the_block_records_open_on_the_ledgers_own_database() {
    let scratch = Scratch::new("records-beside-shares");
    {
        let path = scratch.join("regtest.redb");
        let (mut l, mut records) =
            open_share_ledger(Some(&path), None, Some("regtest"), fixed(u128::MAX)).unwrap();
        l.record(share(1, "alice", 16, hash(1), "")).unwrap();
        records.record_block(found(1, l.cumulative_work())).unwrap();
    }
    let records = BlockRecords::open_file(&scratch.join("regtest.redb")).unwrap();
    assert_eq!(records.blocks(), &[found(1, 16)], "read without opening the share window");
    drop(records);
    let (l, _) = open(&scratch, u128::MAX, None);
    assert_eq!(l.len(), 1);
}

#[test]
fn work_since_sums_only_the_shares_at_or_after_the_cutoff() {
    let mut l = fixed(u128::MAX);
    l.record(share(100, "alice", 16, hash(1), "")).unwrap();
    l.record(share(200, "alice", 16, hash(2), "")).unwrap();
    l.record(share(200, "bob", 32, hash(3), "")).unwrap();
    assert_eq!(l.work_since(150), 48);
    let by_identity = l.work_since_by_identity(150);
    assert_eq!(by_identity.get("alice"), Some(&16));
    assert_eq!(by_identity.get("bob"), Some(&32));
    assert_eq!(l.work_since(0), 64, "a cutoff before every share reads the whole window");
    assert_eq!(l.work_since(300), 0, "a cutoff after every share reads none");
    assert!(l.work_since_by_identity(300).is_empty());
    assert_eq!(l.work_since(200), 48);
    assert_eq!(
        l.work_since_by_identity(150).values().sum::<u128>(),
        l.work_since(150),
        "the two queries read the same shares"
    );
}
