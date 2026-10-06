//! The share window, the split over it, and the store on disk.

use super::*;
use crate::fixtures::{Scratch, found, hash, payout, share};
use crate::ledger::split::{Payout, SplitPolicy};

fn work_by_identity(l: &Ledger) -> Vec<(String, u128)> {
    l.identities().into_iter().map(|(id, s)| (id, s.work)).collect()
}

fn identity_work(identity: &str, work: u128) -> (String, u128) {
    (identity.to_string(), work)
}

fn tags_of(l: &Ledger) -> HashMap<String, String> {
    l.identities().into_iter().map(|(id, s)| (id, s.tag_secondary)).collect()
}

/// Every share the ledger file stores, oldest first.
fn dumped(path: &Path) -> Vec<Share> {
    let mut out = Vec::new();
    dump_file(path, |share| {
        out.push(share);
        Ok(())
    })
    .unwrap();
    out
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

/// The re-read a widening left due, run as `reread` runs it, on a ledger the test owns.
fn reread_now(l: &mut Ledger) -> usize {
    let Some(reread) = l.begin_reread() else { return 0 };
    let read = reread.read();
    l.finish_reread(reread.window, read).0
}

/// `set_network_difficulty` and the re-read it leaves due, as the node watcher runs them.
fn resize(l: &mut Ledger, network_difficulty: f64) -> usize {
    l.set_network_difficulty(network_difficulty);
    reread_now(l)
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
    assert_eq!(split.iter().map(|p| &*p.identity).collect::<Vec<_>>(), vec!["a", "b"]);
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
    const CAP: usize = 64;
    let mut l = fixed(u128::MAX);
    l.set_max_shares(CAP);
    for i in 0..(CAP + 50) {
        l.record(share(i as u64, "a", 1, hash(i as u64), "")).unwrap();
    }
    assert_eq!(l.len(), CAP);
    assert_eq!(l.total_work(), CAP as u128);
    assert_eq!(work_by_identity(&l), vec![identity_work("a", CAP as u128)]);
    assert!(l.count_capped(), "the count bound, not the window, ends the payout set");
    assert_eq!(l.accepted_times().last(), Some(&((CAP + 49) as u64)), "the newest are kept");
}

#[test]
fn the_count_bound_defaults_to_max_shares() {
    assert_eq!(fixed(u128::MAX).max_shares(), MAX_SHARES);
}

#[test]
fn a_window_within_the_count_bound_is_not_capped() {
    let mut l = fixed(1_000);
    l.set_max_shares(64);
    for i in 0..40u64 {
        l.record(share(i, "a", 1, hash(i), "")).unwrap();
    }
    assert!(!l.count_capped(), "the work target is what the window is still filling towards");
    assert_eq!(l.len(), 40);
}

#[test]
fn window_tracks_network_difficulty() {
    let rule = WindowRule { multiple: 8.0 };
    assert_eq!(rule.window_for(1_000.0), 8_000);
    assert_eq!(rule.window_for(4.6e-10), 1);
    assert_eq!(rule.window_for(f64::NAN), 1);
    assert_eq!(rule.window_for(0.0), 1);
    assert_eq!(WindowRule::fixed(64).window_for(1.0), 64);
}

#[test]
fn the_network_difficulty_sizes_the_window() {
    let mut l = Ledger::new(WindowRule { multiple: 16.0 }, SplitPolicy::default());
    assert_eq!(l.window(), 16, "sized to a difficulty of 1 until one is set");
    for i in 0..4 {
        l.record(share(i, "a", 16, hash(i), "")).unwrap();
    }
    assert_eq!(l.total_work(), 16);
    assert!(!l.set_network_difficulty(2.0), "no store to re-read");
    assert_eq!(l.window(), 32);
    l.record(share(4, "a", 16, hash(4), "")).unwrap();
    assert_eq!(l.total_work(), 32, "the wider window keeps two shares");
}

#[test]
fn the_split_takes_the_operator_fee_and_the_minimum_from_the_policy() {
    let policy = SplitPolicy { fee_bps: 100 };
    let mut l = Ledger::new(WindowRule::fixed(u128::MAX), policy);
    for (i, (identity, difficulty)) in [("a", 99u64), ("b", 1)].into_iter().enumerate() {
        l.record(share(i as u64, identity, difficulty, hash(i as u64), "")).unwrap();
    }
    assert_eq!(l.split_policy().fee_on(50_000), 500);
    assert_eq!(
        l.split(50_000),
        vec![payout("a", 49_500)],
        "the 49_500 after the fee is split, and b's 495 of it is under the minimum"
    );
}

fn open_file(
    path: &Path,
    window: u128,
    keep: Option<u64>,
    chain: Option<&str>,
) -> io::Result<(Ledger, ReadBack)> {
    let mut l = fixed(window);
    let read_back = l.attach(Store::open(path, keep, chain)?)?;
    Ok((l, read_back))
}

fn open(scratch: &Scratch, window: u128, keep: Option<u64>) -> (Ledger, ReadBack) {
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

fn ledger_with_tags(shares: &[(&str, u64, &str)]) -> Ledger {
    let mut l = fixed(1_000_000);
    for (i, (identity, difficulty, tag)) in shares.iter().enumerate() {
        l.record(share(1_000 + i as u64, identity, *difficulty, hash(i as u64), tag)).unwrap();
    }
    l
}

/// Shares under a mixture of secondary tags: 351 work, bob's under two tags.
const TAGGED: &[(&str, u64, &str)] = &[
    ("alice", 100, "public"),
    ("bob", 100, "own"),
    ("carol", 37, "public"),
    ("dave", 63, ""),
    ("bob", 50, "public"),
    ("erin", 1, "public"),
];

fn tagged_split() -> Vec<Payout> {
    vec![
        payout("bob", 150),
        payout("alice", 100),
        payout("dave", 63),
        payout("carol", 37),
        payout("erin", 1),
    ]
}

#[test]
fn the_split_pays_by_work_whatever_the_secondary_tags() {
    let l = ledger_with_tags(TAGGED);
    let untagged: Vec<(&str, u64, &str)> =
        TAGGED.iter().map(|(identity, work, _)| (*identity, *work, "")).collect();
    let plain = ledger_with_tags(&untagged);
    assert_eq!(l.split_value(351, 0, 512), tagged_split());
    assert_eq!(l.split_value(351, 0, 512), plain.split_value(351, 0, 512));
    assert_eq!(l.split_value(1_000_000, 0, 2), plain.split_value(1_000_000, 0, 2));
    assert_eq!(l.split_value(1_000, 100, 512), plain.split_value(1_000, 100, 512));
    assert_eq!(tags_of(&l).get("bob").map(String::as_str), Some("public"), "the tag is held");
}

/// `split_value` divides by the weights' total, so that total must equal the window's work
/// exactly, and each weight an identity's work, whatever the tags and after every trim.
#[test]
fn weights_total_the_window() {
    let mut l = ledger_with_tags(TAGGED);
    for window in [1_000_000u128, 200, 64, 1] {
        l.set_window(window);
        let w = l.weights();
        let total: u128 = w.entries.iter().map(|(_, w)| w).sum();
        assert_eq!(total, l.total_work(), "window {window}");
        let by_identity: HashMap<&str, u128> =
            w.entries.iter().map(|(identity, w)| (&**identity, *w)).collect();
        let identities = l.identities();
        assert_eq!(by_identity.len(), identities.len(), "window {window}");
        for (identity, state) in &identities {
            assert_eq!(by_identity[identity.as_str()], state.work, "window {window}: {identity}");
        }
    }
}

#[test]
fn a_window_of_tagged_shares_reads_back_the_same_work() {
    let scratch = Scratch::new("tagged-read-back");
    let (total, by_identity, tags) = {
        let (mut l, _) = open(&scratch, 1_000_000, None);
        for (i, (identity, difficulty, tag)) in TAGGED.iter().enumerate() {
            l.record(share(1_000 + i as u64, identity, *difficulty, hash(i as u64), tag)).unwrap();
        }
        (l.total_work(), work_by_identity(&l), tags_of(&l))
    };
    let (reopened, read_back) = open(&scratch, 1_000_000, None);
    assert_eq!(read_back.skipped, 0);
    assert_eq!(reopened.total_work(), total);
    assert_eq!(work_by_identity(&reopened), by_identity);
    assert_eq!(tags_of(&reopened), tags);
    assert_eq!(reopened.split_value(351, 0, 512), tagged_split());
    drop(reopened);
    let stored: Vec<String> =
        dumped(&scratch.join("regtest.redb")).into_iter().map(|s| s.tag_secondary).collect();
    let recorded: Vec<&str> = TAGGED.iter().map(|(_, _, tag)| *tag).collect();
    assert_eq!(stored, recorded, "every share keeps its tag on disk");
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
fn the_window_is_read_back_across_a_restart_oldest_first() {
    let scratch = Scratch::new("window-restart");
    {
        let (mut l, _) = open(&scratch, 1_000_000, None);
        l.record(share(1, "alice", 16, hash(1), "")).unwrap();
        l.record(share(2, "bob", 32, hash(2), "")).unwrap();
    }
    let (l, _) = open(&scratch, 1_000_000, None);
    assert_eq!(l.accepted_times(), vec![1, 2], "oldest first");
}

#[test]
fn accepted_times_are_the_shares_the_window_holds() {
    let mut l = ledger_with(1_000_000, &[("alice", 16), ("bob", 32)]);
    l.record(share(1_100, "carol", 8, hash(99), "")).unwrap();
    assert_eq!(l.accepted_times(), vec![1_000, 1_001, 1_100]);

    let mut narrow = fixed(8);
    narrow.record(share(1, "alice", 8, hash(1), "")).unwrap();
    narrow.record(share(2, "bob", 8, hash(2), "")).unwrap();
    assert_eq!(narrow.accepted_times(), vec![2]);
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
    assert_eq!(l.accepted_times().last(), Some(&999), "and the newest work is in it");
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
    assert!(!l.set_window(8));
    assert_eq!(work_by_identity(&l), vec![identity_work("carol", 8)]);
    assert!(!l.set_window(1_000_000), "no store to read the trimmed shares back from");
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

    assert!(!l.set_window(8));
    assert_eq!(work_by_identity(&l), vec![identity_work("carol", 8)]);
    assert_eq!(l.accepted_times(), vec![3]);

    assert!(l.set_window(56), "a re-read is due");
    assert_eq!(work_by_identity(&l), vec![identity_work("carol", 8)], "until it runs");
    assert_eq!(reread_now(&mut l), 2, "alice and bob are re-read");
    assert_eq!(l.total_work(), 56);
    assert_eq!(
        work_by_identity(&l),
        vec![identity_work("bob", 32), identity_work("alice", 16), identity_work("carol", 8)]
    );
    assert_eq!(l.accepted_times(), vec![1, 2, 3]);
}

/// Disk cannot be bounded below what the window needs, since the window reads itself back
/// from these rows: `--ledger-keep-shares` is a request and the window is the floor.
#[test]
fn retention_never_removes_a_share_the_window_holds() {
    let scratch = Scratch::new("retain-floor");
    let (mut l, _) = open(&scratch, 1_000_000, Some(2));
    for i in 0..10u64 {
        l.record(share(i, "alice", 16, hash(i), "")).unwrap();
    }
    assert_eq!(l.len(), 10, "the window holds every share, well past the two asked for");
    drop(l);
    let dumped = dumped(&scratch.join("regtest.redb"));
    assert_eq!(dumped.len(), 10, "so every one is still on disk to read back");
}

#[test]
fn retention_removes_what_is_past_the_window_and_the_configured_count() {
    const APART: u64 = 5 * ratum::SECS_PER_HOUR;
    let scratch = Scratch::new("retain-past-window");
    let (mut l, _) = open(&scratch, 32, Some(3));
    for i in 0..10u64 {
        l.record(share(i * APART, "alice", 16, hash(i), "")).unwrap();
    }
    assert_eq!(l.len(), 2, "a window of 32 work holds two shares of 16");
    drop(l);
    let dumped = dumped(&scratch.join("regtest.redb"));
    assert_eq!(dumped.len(), 3, "the configured count, which is above the window's two");
    assert_eq!(dumped.first().unwrap().accepted_at, 7 * APART, "the newest three");
}

/// The duplicate check reads back the hashes accepted within `ACCEPTED_HASH_RETENTION_SECS` at
/// startup, so retention keeps those rows whatever `--ledger-keep-shares` asks for.
#[test]
fn retention_never_removes_a_share_accepted_within_the_duplicate_retention() {
    const APART: u64 = ratum::SECS_PER_HOUR;
    let scratch = Scratch::new("retain-duplicates");
    let (mut l, _) = open(&scratch, 16, Some(1));
    for i in 0..10u64 {
        l.record(share(i * APART, "alice", 16, hash(i), "")).unwrap();
    }
    assert_eq!(l.len(), 1, "the window holds only the newest");
    let newest = 9 * APART;
    assert_eq!(
        l.accepted_since(newest - ACCEPTED_HASH_RETENTION_SECS, 100).unwrap().len(),
        5,
        "the five accepted in the 4 hours 10 minutes to the newest are kept for the restart"
    );
    drop(l);
    let dumped = dumped(&scratch.join("regtest.redb"));
    assert_eq!(dumped.len(), 5, "and only those, however few were asked for");
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
    let dumped = dumped(&scratch.join("regtest.redb"));
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

#[test]
fn accepted_since_reads_the_newest_rows_back_to_the_cutoff_oldest_first() {
    let scratch = Scratch::new("accepted-since");
    let (mut l, _) = open(&scratch, 16, None);
    for (i, at) in [100u64, 200, 300, 400, 500].into_iter().enumerate() {
        l.record(share(at, "alice", 16, hash(i as u64), "")).unwrap();
    }
    assert_eq!(
        l.accepted_since(300, 10).unwrap(),
        vec![(300, hash(2)), (400, hash(3)), (500, hash(4))],
        "from the cutoff on, even though the window holds only the newest share"
    );
    assert_eq!(l.accepted_since(300, 2).unwrap(), vec![(400, hash(3)), (500, hash(4))]);
    assert!(fixed(16).accepted_since(0, 10).unwrap().is_empty(), "a file-less ledger has none");
}

/// The window as it was held before its shares were reduced to 16 bytes: every share whole in a
/// deque, identities by name, and a widening read back from the full history of recorded
/// shares, as the ledger file holds them after retention. `count_capped` follows the current
/// rule, the bound held with less work than the target, where the old window set it only
/// when a trim cut on the count. `the_compact_window_matches_*` drive
/// it beside `Ledger` and compare everything a caller can read.
struct Reference {
    shares: VecDeque<Share>,
    identities: HashMap<String, IdentityState>,
    total_work: u128,
    window: u128,
    max_shares: usize,
    count_capped: bool,
    history: Vec<Share>,
    has_store: bool,
    /// `--ledger-keep-shares`, pruning `history` as the store's retention prunes its rows.
    keep: Option<usize>,
}

impl Reference {
    fn new(window: u128, has_store: bool, keep: Option<usize>) -> Self {
        Self {
            shares: VecDeque::new(),
            identities: HashMap::new(),
            total_work: 0,
            window,
            max_shares: MAX_SHARES,
            count_capped: false,
            history: Vec::new(),
            has_store,
            keep,
        }
    }

    fn push(&mut self, share: Share) {
        self.total_work += u128::from(share.difficulty);
        let state = self.identities.entry(share.identity.clone()).or_default();
        state.work += u128::from(share.difficulty);
        state.tag_secondary.clone_from(&share.tag_secondary);
        self.shares.push_back(share);
    }

    fn trim(&mut self) {
        while self.shares.len() > 1 && self.total_work > self.window {
            let over = self.total_work - self.window;
            if u128::from(self.shares.front().unwrap().difficulty) > over {
                break;
            }
            self.drop_oldest();
        }
        while self.shares.len() > self.max_shares {
            self.drop_oldest();
        }
        self.count_capped = self.shares.len() >= self.max_shares && self.total_work < self.window;
    }

    fn drop_oldest(&mut self) {
        let Some(oldest) = self.shares.pop_front() else { return };
        self.total_work -= u128::from(oldest.difficulty);
        let Some(state) = self.identities.get_mut(&oldest.identity) else { return };
        state.work -= u128::from(oldest.difficulty);
        if state.work == 0 {
            self.identities.remove(&oldest.identity);
        }
    }

    fn record(&mut self, share: Share) {
        let keep_after = share.accepted_at.saturating_sub(ACCEPTED_HASH_RETENTION_SECS);
        self.history.push(share.clone());
        self.push(share);
        self.trim();
        if let Some(keep) = self.keep {
            let surplus = self.history.len().saturating_sub(keep.max(self.shares.len()));
            let removable =
                self.history.iter().take(surplus).take_while(|s| s.accepted_at < keep_after);
            let removable = removable.count();
            self.history.drain(..removable);
        }
    }

    fn set_window(&mut self, window: u128) {
        let window = window.max(1);
        let widened = window > self.window;
        self.window = window;
        if widened && self.has_store {
            let mut collected = Vec::new();
            let mut work = 0u128;
            for s in self.history.iter().rev() {
                if work >= self.window || collected.len() >= self.max_shares {
                    break;
                }
                work += u128::from(s.difficulty);
                collected.push(s.clone());
            }
            self.shares.clear();
            self.identities.clear();
            self.total_work = 0;
            for s in collected.into_iter().rev() {
                self.push(s);
                self.trim();
            }
        }
        self.trim();
    }

    fn set_max_shares(&mut self, max_shares: usize) {
        self.max_shares = max_shares.max(1);
        self.trim();
    }

    fn identities(&self) -> Vec<(String, IdentityState)> {
        let mut v: Vec<_> = self.identities.iter().map(|(n, s)| (n.clone(), s.clone())).collect();
        v.sort_by(|(a, x), (b, y)| most_work_first((a, x.work), (b, y.work)));
        v
    }

    fn work_since_by_identity(&self, cutoff: u64) -> HashMap<String, u128> {
        let mut by_identity = HashMap::new();
        for s in self.shares.iter().rev().take_while(|s| s.accepted_at >= cutoff) {
            *by_identity.entry(s.identity.clone()).or_insert(0) += u128::from(s.difficulty);
        }
        by_identity
    }
}

/// A seeded xorshift, so a failing run of the equivalence test replays exactly.
struct XorShift(u64);

impl XorShift {
    fn below(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % n
    }
}

/// `seconds_apart` is the most time between two shares, in units a random 0 to 2 multiplies.
fn drive_beside_the_reference(
    l: &mut Ledger,
    r: &mut Reference,
    seed: u64,
    steps: u64,
    seconds_apart: u64,
) {
    const NAMES: [&str; 6] = ["alice", "bob", "carol", "dave", "erin", "frank"];
    const TAGS: [&str; 3] = ["", "public", "own"];
    let mut rng = XorShift(seed);
    let mut now = 1_000u64;
    for step in 0..steps {
        match rng.below(100) {
            0..=79 => {
                now += rng.below(3) * seconds_apart;
                let difficulty =
                    if rng.below(2) == 0 { 1 << rng.below(6) } else { 1 + rng.below(40) };
                let s = share(
                    now,
                    NAMES[rng.below(6) as usize],
                    difficulty,
                    hash(step),
                    TAGS[rng.below(3) as usize],
                );
                l.record(s.clone()).unwrap();
                r.record(s);
            }
            80..=91 => {
                let window = 1 + u128::from(rng.below(600));
                l.set_window(window);
                reread_now(l);
                r.set_window(window);
            }
            _ => {
                let max = if rng.below(4) == 0 { 1_000 } else { 1 + rng.below(40) as usize };
                l.set_max_shares(max);
                r.set_max_shares(max);
            }
        }
        let at = |what: &str| format!("seed {seed} step {step}: {what}");
        assert_eq!(l.identities(), r.identities(), "{}", at("identities"));
        assert_eq!(l.total_work(), r.total_work, "{}", at("total work"));
        assert_eq!(l.len(), r.shares.len(), "{}", at("share count"));
        assert_eq!(l.count_capped(), r.count_capped, "{}", at("count capped"));
        let times: Vec<u64> = r.shares.iter().map(|s| s.accepted_at).collect();
        assert_eq!(l.accepted_times(), times, "{}", at("the shares held"));
        let cutoff = now.saturating_sub(4);
        assert_eq!(
            l.work_since_by_identity(cutoff),
            r.work_since_by_identity(cutoff),
            "{}",
            at("recent work")
        );
        assert_eq!(
            l.work_since(cutoff),
            r.work_since_by_identity(cutoff).values().sum(),
            "{}",
            at("recent total")
        );
    }
}

#[test]
fn the_compact_window_matches_the_whole_share_window_file_less() {
    for seed in [1, 0x5eed, 0xdead_beef, 0x0123_4567_89ab_cdef] {
        let mut l = fixed(200);
        let mut r = Reference::new(200, false, None);
        drive_beside_the_reference(&mut l, &mut r, seed, 3_000, 1);
    }
}

#[test]
fn the_compact_window_matches_the_whole_share_window_read_back_from_a_store() {
    for seed in [7, 0xfeed_f00d] {
        let scratch = Scratch::new(&format!("equivalence-{seed}"));
        let mut l = fixed(200);
        l.attach(Store::open(&scratch.join("regtest.redb"), None, Some("regtest")).unwrap())
            .unwrap();
        let mut r = Reference::new(200, true, None);
        drive_beside_the_reference(&mut l, &mut r, seed, 1_500, 1);
    }
}

/// Retention on, and shares 50 minutes apart at most so the 4 hours 10 minutes the duplicate
/// check keeps cover only a few: a widening then reads back less than the window asks for.
#[test]
fn the_compact_window_matches_the_whole_share_window_read_back_from_a_pruned_store() {
    const KEEP: u64 = 30;
    for seed in [11, 0xabad_cafe] {
        let scratch = Scratch::new(&format!("equivalence-pruned-{seed}"));
        let mut l = fixed(200);
        let store = Store::open(&scratch.join("regtest.redb"), Some(KEEP), Some("regtest"));
        l.attach(store.unwrap()).unwrap();
        let mut r = Reference::new(200, true, Some(KEEP as usize));
        drive_beside_the_reference(&mut l, &mut r, seed, 1_500, 3_000);
    }
}

#[test]
fn a_read_that_fails_part_way_leaves_the_window_as_it_was() {
    let mut l = ledger_with(1_000_000, &[("alice", 16), ("bob", 32)]);
    let before = (l.identities(), l.total_work(), l.accepted_times(), l.count_capped());
    let failed = l.load_from(|push| {
        push(WindowRow::Count(1));
        push(WindowRow::Share(share(5_000, "carol", 8, hash(50), "")));
        Err(io::Error::other("the file stopped reading"))
    });
    assert!(failed.is_err());
    assert_eq!((l.identities(), l.total_work(), l.accepted_times(), l.count_capped()), before);
    l.record(share(5_001, "carol", 8, hash(51), "")).unwrap();
    assert_eq!(l.total_work(), 56, "and records on from there");
}

#[test]
fn a_read_back_allocates_the_window_once_at_its_size() {
    let scratch = Scratch::new("read-back-size");
    {
        let (mut l, _) = open(&scratch, u128::MAX, None);
        for i in 0..1_000u64 {
            l.record(share(i, "alice", 16, hash(i), "")).unwrap();
        }
    }
    let (mut l, _) = open(&scratch, u128::MAX, None);
    let read_back = l.contents.shares.capacity();
    assert_eq!(l.len(), 1_000);
    assert!((1_001..1_100).contains(&read_back), "one slot over, not 1024: {read_back}");
    l.record(share(1_000, "alice", 16, hash(1_000), "")).unwrap();
    assert_eq!(
        l.contents.shares.capacity(),
        read_back,
        "which the next share takes without growing"
    );
    for i in 1_001..1_200u64 {
        l.record(share(i, "alice", 16, hash(i), "")).unwrap();
    }
    assert!(
        l.contents.shares.capacity() <= 1_200 + 1_200 / 8,
        "a growing window grows its buffer by an eighth, not by doubling: {}",
        l.contents.shares.capacity()
    );
}

#[test]
fn at_the_bound_the_window_grows_by_one_slot_not_by_doubling() {
    let mut l = fixed(u128::MAX);
    l.set_max_shares(64);
    for i in 0..64u64 {
        l.record(share(i, "a", 1, hash(i), "")).unwrap();
    }
    l.contents.shares.shrink_to_fit();
    for i in 64..200u64 {
        l.record(share(i, "a", 1, hash(i), "")).unwrap();
    }
    assert!(l.contents.shares.capacity() <= 65, "capacity {}", l.contents.shares.capacity());
}

#[test]
fn a_read_back_that_stops_at_the_share_bound_is_count_capped_at_once() {
    let scratch = Scratch::new("capped-read-back");
    {
        let (mut l, _) = open(&scratch, u128::MAX, None);
        for i in 0..10u64 {
            l.record(share(i, "alice", 16, hash(i), "")).unwrap();
        }
    }
    let mut l = fixed(u128::MAX);
    l.set_max_shares(4);
    l.attach(Store::open(&scratch.join("regtest.redb"), None, Some("regtest")).unwrap()).unwrap();
    assert_eq!(l.len(), 4);
    assert!(l.count_capped(), "before another share is recorded");
}

/// Hides the store's share table under another name, or restores it, so a read of the window
/// fails as a read of a damaged file does.
fn hide_share_table(l: &Ledger, hidden: bool) {
    const SHARES: redb::TableDefinition<u64, &[u8]> = redb::TableDefinition::new("shares");
    const HIDDEN: redb::TableDefinition<u64, &[u8]> = redb::TableDefinition::new("hidden_shares");
    let (from, to) = if hidden { (SHARES, HIDDEN) } else { (HIDDEN, SHARES) };
    let db = l.store.as_ref().expect("a ledger with a store").database();
    db::write(&db, |w| {
        use db::DbResult as _;
        w.rename_table(from, to).db()
    })
    .unwrap();
}

#[test]
fn a_widening_whose_read_failed_is_read_again_at_the_same_difficulty() {
    let scratch = Scratch::new("widen-retry");
    let mut l = Ledger::new(WindowRule { multiple: 1.0 }, SplitPolicy::default());
    l.attach(Store::open(&scratch.join("regtest.redb"), None, Some("regtest")).unwrap()).unwrap();
    assert_eq!(resize(&mut l, 56.0), 0, "nothing stored to re-read");
    l.record(share(1, "alice", 16, hash(1), "")).unwrap();
    l.record(share(2, "bob", 32, hash(2), "")).unwrap();
    l.record(share(3, "carol", 8, hash(3), "")).unwrap();
    assert_eq!(resize(&mut l, 8.0), 0, "narrowing reads nothing");
    assert_eq!(l.accepted_times(), vec![3]);
    assert_eq!(l.network_difficulty(), Some(8.0));

    hide_share_table(&l, true);
    assert_eq!(resize(&mut l, 56.0), 0, "the read fails");
    assert_eq!(l.window(), 56, "the window is at its new size");
    assert_eq!(l.accepted_times(), vec![3], "holding the shares it held");
    assert_eq!(resize(&mut l, 56.0), 0, "and fails again while the table is hidden");

    hide_share_table(&l, false);
    assert_eq!(resize(&mut l, 56.0), 2, "the same difficulty re-reads alice and bob");
    assert_eq!(l.accepted_times(), vec![1, 2, 3]);
    assert_eq!(l.total_work(), 56);
    assert_eq!(resize(&mut l, 56.0), 0, "once read, the same difficulty reads nothing");
}

#[test]
fn a_read_back_of_no_shares_empties_the_window_and_clears_count_capped() {
    let mut l = fixed(u128::MAX);
    l.set_max_shares(4);
    for i in 0..6u64 {
        l.record(share(i, "alice", 16, hash(i), "")).unwrap();
    }
    assert!(l.count_capped());
    let read = l.load_from(|_| Ok(ReadBack::default()));
    assert_eq!(read.unwrap(), ReadBack::default());
    assert!(l.is_empty());
    assert_eq!(l.total_work(), 0);
    assert!(!l.count_capped(), "an empty window holds fewer shares than the bound");
}

#[test]
fn the_network_difficulty_is_the_one_last_set() {
    let mut l = Ledger::new(WindowRule { multiple: 8.0 }, SplitPolicy::default());
    assert_eq!(l.network_difficulty(), None, "none before the node is read");
    l.set_network_difficulty(4.0);
    assert_eq!(l.network_difficulty(), Some(4.0));
    l.set_network_difficulty(4.0625);
    assert_eq!(l.network_difficulty(), Some(4.0625), "recorded when the window keeps its size");
    assert_eq!(l.window(), 32);
}

/// A widening's re-read reads a snapshot taken when it begins: a share recorded while it runs
/// is credited to the narrower window, then added to the wider one once.
#[test]
fn a_share_recorded_while_the_window_is_re_read_is_in_the_wider_window_once() {
    let scratch = Scratch::new("record-during-reread");
    let (mut l, _) = open(&scratch, 56, None);
    l.record(share(1, "alice", 16, hash(1), "")).unwrap();
    l.record(share(2, "bob", 32, hash(2), "")).unwrap();
    l.record(share(3, "carol", 8, hash(3), "")).unwrap();
    assert!(!l.set_window(8));
    assert!(l.set_window(64));
    let reread = l.begin_reread().expect("a re-read is due");
    assert!(l.begin_reread().is_none(), "one runs at a time");
    l.record(share(4, "dave", 8, hash(4), "")).unwrap();
    assert_eq!(
        work_by_identity(&l),
        vec![identity_work("carol", 8), identity_work("dave", 8)],
        "the narrower window credits it meanwhile"
    );
    let read = reread.read();
    assert_eq!(l.finish_reread(reread.window, read).0, 2, "alice and bob are re-read");
    assert_eq!(l.accepted_times(), vec![1, 2, 3, 4]);
    assert_eq!(l.total_work(), 64);
    assert_eq!(reread_now(&mut l), 0, "none is due once it is installed");
}

#[test]
fn a_window_widened_again_while_it_is_re_read_is_re_read_again() {
    let scratch = Scratch::new("widen-during-reread");
    let (mut l, _) = open(&scratch, 56, None);
    l.record(share(1, "alice", 16, hash(1), "")).unwrap();
    l.record(share(2, "bob", 32, hash(2), "")).unwrap();
    l.record(share(3, "carol", 8, hash(3), "")).unwrap();
    assert!(!l.set_window(8));
    assert!(l.set_window(24));
    let reread = l.begin_reread().expect("a re-read is due");
    assert!(l.set_window(56), "still due");
    let read = reread.read();
    assert_eq!(l.finish_reread(reread.window, read).0, 1, "bob, read to 24");
    assert_eq!(l.accepted_times(), vec![2, 3]);
    assert_eq!(reread_now(&mut l), 1, "and alice by the next re-read, to 56");
    assert_eq!(l.accepted_times(), vec![1, 2, 3]);
}

/// Retention's floor is the window's share count, the narrower window's while a re-read runs:
/// it waits, so the rows the wider window holds stay on disk.
#[test]
fn retention_waits_for_a_running_re_read() {
    const APART: u64 = 5 * ratum::SECS_PER_HOUR;
    let scratch = Scratch::new("retain-during-reread");
    let (mut l, _) = open(&scratch, 56, Some(1));
    l.record(share(0, "alice", 16, hash(1), "")).unwrap();
    l.record(share(APART, "bob", 32, hash(2), "")).unwrap();
    l.record(share(2 * APART, "carol", 8, hash(3), "")).unwrap();
    assert!(!l.set_window(8));
    assert!(l.set_window(64));
    let reread = l.begin_reread().expect("a re-read is due");
    assert_eq!(l.record(share(3 * APART, "dave", 8, hash(4), "")).unwrap(), 0, "none removed");
    let read = reread.read();
    l.finish_reread(reread.window, read);
    assert_eq!(l.accepted_times(), vec![0, APART, 2 * APART, 3 * APART]);
    drop(l);
    assert_eq!(dumped(&scratch.join("regtest.redb")).len(), 4, "each on disk");
}

/// The ledger lock's holds by a widening that re-reads `RE_READ` shares, `CREDITED` recorded
/// meanwhile, and the longest a coinbaser answer (`Ledger::weights_for`) waits for the lock.
#[test]
#[ignore = "measures the ledger lock's holds on the drive TMPDIR names; run with --release -- --ignored --nocapture"]
fn widening_lock_hold() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};
    /// What block 975744's widening re-read.
    const RE_READ: u64 = 226_929;
    /// About 1000 a second over the 8 seconds block 975744's re-read took.
    const CREDITED: u64 = 8_192;
    const STORED: u64 = MAX_SHARES as u64 - CREDITED;
    const DIFFICULTY: u64 = 16;
    let shares = |from: u64, to: u64| -> Vec<Share> {
        let miner = |i: u64| format!("miner{:02}", i % 32);
        (from..to).map(|i| share(1_000 + i, &miner(i), DIFFICULTY, hash(i), "")).collect()
    };
    let scratch = Scratch::new("widening-lock-hold");
    let (mut l, _) = open(&scratch, u128::MAX, None);
    for from in (0..STORED).step_by(4096) {
        l.record_batch(shares(from, (from + 4096).min(STORED))).unwrap();
    }
    assert!(!l.set_window(u128::from((STORED - RE_READ) * DIFFICULTY)));
    let ledger = Mutex::new(l);
    let began = Instant::now();
    let reread = {
        let mut l = lock(&ledger);
        assert!(l.set_window(u128::from(MAX_SHARES as u64 * DIFFICULTY)));
        l.begin_reread().expect("a re-read is due")
    };
    let begin_hold = began.elapsed();
    for from in (STORED..STORED + CREDITED).step_by(4096) {
        lock(&ledger).record_batch(shares(from, from + 4096)).unwrap();
    }
    let stop = AtomicBool::new(false);
    std::thread::scope(|s| {
        let probe = s.spawn(|| {
            let (mut longest, mut answered) = (Duration::ZERO, 0u64);
            while !stop.load(Ordering::Relaxed) {
                let asked = Instant::now();
                drop(lock(&ledger).weights_for(312_500_000));
                longest = longest.max(asked.elapsed());
                answered += 1;
            }
            (longest, answered)
        });
        let reading = Instant::now();
        let read = reread.read();
        let read_took = reading.elapsed();
        let installing = Instant::now();
        let (re_read, replaced) = lock(&ledger).finish_reread(reread.window, read);
        let install_hold = installing.elapsed();
        drop(replaced);
        std::thread::sleep(Duration::from_millis(50));
        stop.store(true, Ordering::Relaxed);
        let (longest, answered) = probe.join().unwrap();
        assert_eq!(re_read as u64, RE_READ);
        assert_eq!(lock(&ledger).len(), MAX_SHARES);
        println!(
            "read {STORED} rows in {:.3} s; the lock was held {:.6} s to begin the re-read and \
             {:.6} s to install it with {CREDITED} shares credited meanwhile; the longest of \
             {answered} lock takes during the read and install waited {:.6} s",
            read_took.as_secs_f64(),
            begin_hold.as_secs_f64(),
            install_hold.as_secs_f64(),
            longest.as_secs_f64()
        );
    });
}
