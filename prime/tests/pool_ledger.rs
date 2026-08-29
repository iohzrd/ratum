//! The share window as the binary builds it at startup: what it reads back from the ledger,
//! how large it makes the window, and who it pays as a result.

mod support;

use ratum::datum::messages::{CoinbaserRequest, CoinbaserResponse, server_subcmd};
use ratum_prime::ledger::Ledger;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use support::{FakeNode, Pool, PoolArgs, TempDir, printed, run_pool, script_for_address};

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// A distinct proof-of-work hash for each seeded share, as real shares have; the ledger
/// stores a hash once, so reusing one would not store the later share.
fn next_hash() -> [u8; 32] {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&NEXT.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    h
}

/// The default ledger inside a data directory: named after the chain the node reports, and
/// the fake node reports regtest.
fn ledger_path(dir: &TempDir) -> std::path::PathBuf {
    dir.join("regtest.redb")
}

/// Record `count` shares of `difficulty` each into the ledger at `path`, alternating between
/// two miners, then close it so the pool can open it.
fn seed(path: &std::path::Path, count: usize, difficulty: u64) {
    let (mut ledger, _) =
        Ledger::open(path, u128::MAX, None, Some("regtest")).expect("open the seed ledger");
    for i in 0..count {
        let who = if i % 4 == 0 { "alice" } else { "bob" };
        let at = now() - (count - i) as u64;
        ledger.record(at, who, difficulty, &next_hash()).expect("seed a share");
    }
}

/// A window sized from `--window-floor` at startup would discard everything the ledger held,
/// and the next block would pay whoever had submitted the most recent share. The window must
/// come from the node's difficulty.
#[test]
fn the_window_is_sized_from_the_node_at_startup() {
    let node = FakeNode::start();
    node.set_difficulty(12_800.0); // eight times this is 102,400 units of work
    let dir = TempDir::new("window-from-node");
    seed(&ledger_path(&dir), 100, 1024);

    let pool = Pool::start(
        dir,
        PoolArgs { rpc_url: Some(node.url()), window_floor: 1, ..Default::default() },
    );
    let line = pool.expect_line("share window from");
    assert!(line.contains("100 shares"), "the whole ledger should be in the window: {line}");
    assert!(line.contains("102400 work"), "{line}");
    assert!(
        pool.expect_line("payouts:").contains("102400 at startup"),
        "the startup window is reported"
    );
}

#[test]
fn a_floor_above_eight_times_the_node_difficulty_sets_the_window() {
    let dir = TempDir::new("window-floor");
    seed(&ledger_path(&dir), 100, 1024);
    let pool = Pool::start(dir, PoolArgs { window_floor: 4096, ..Default::default() });

    let line = pool.expect_line("share window from");
    assert!(line.contains("work"), "{line}");
    let work: u128 = line
        .split_whitespace()
        .nth_back(1)
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("cannot read the work out of {line:?}"));
    assert!(work >= 4096, "the window is at least the floor: {line}");
    assert!(work < 4096 + 1024, "and nothing beyond it is kept: {line}");
}

#[test]
fn a_restart_credits_the_same_miners_it_did_before() {
    let node = FakeNode::start();
    node.set_difficulty(0.5); // 8 x 0.5 = 4 units of work, the size of the seeded window
    support::lock(&node.state).coinbase_value = Some(1_000_000);
    let dir = TempDir::new("restart");
    {
        let (mut l, _) =
            Ledger::open(&ledger_path(&dir), u128::MAX, None, None).expect("seed ledger");
        l.record(now(), "alice", 3, &next_hash()).unwrap();
        l.record(now(), "bob", 1, &next_hash()).unwrap();
    }

    let payouts = |pool: &Pool| {
        let mut gateway = pool.connect();
        let _config = gateway.recv();
        gateway.send_mining(&CoinbaserRequest { value: 1_000_000, prev_hash: [0; 32] }.encode());
        let (payload, _) = gateway.recv_until(server_subcmd::COINBASER);
        CoinbaserResponse::decode(&payload).expect("coinbaser response").outputs
    };

    // A second data directory holding a copy of the same ledger, for the restart.
    let dir2 = TempDir::new("restart-second");
    std::fs::copy(ledger_path(&dir), ledger_path(&dir2)).expect("copy the ledger");

    let first = Pool::start(
        dir,
        PoolArgs { rpc_url: Some(node.url()), window_floor: 1, ..Default::default() },
    );
    let before = payouts(&first);
    drop(first);

    let second = Pool::start(
        dir2,
        PoolArgs { rpc_url: Some(node.url()), window_floor: 1, ..Default::default() },
    );
    let after = payouts(&second);

    assert_eq!(before.len(), 2, "both miners are in the window: {before:?}");
    assert_eq!(before, after, "a restart must not change who is owed what");
    assert_eq!(before[0].script, script_for_address("alice"));
    assert_eq!(before[0].value, 750_000);
}

#[test]
fn a_window_the_ledger_cannot_fill_is_reported() {
    let dir = TempDir::new("ledger-short");
    seed(&ledger_path(&dir), 5, 10);
    let pool = Pool::start(dir, PoolArgs { window_floor: 1_000_000, ..Default::default() });
    let line = pool.expect_line("share window from");
    assert!(line.contains("5 shares"), "{line}");
    // The ledger holds less work than the window covers, so the pool logs the shortfall.
    assert!(pool.logged("exceeds the retained ledger"), "the shortfall is reported");
}

#[test]
fn a_missing_ledger_file_is_logged_with_its_path_and_zero_shares() {
    let dir = TempDir::new("no-ledger");
    let pool = Pool::start(
        TempDir::new("no-ledger-home"),
        PoolArgs {
            data_dir: None,
            extra: vec!["--ledger".into(), dir.join("elsewhere.redb").display().to_string()],
            ..Default::default()
        },
    );
    let line = pool.expect_line("share window from");
    assert!(line.contains("elsewhere.redb"), "the ledger path is the one given: {line}");
    assert!(line.contains("0 shares"), "{line}");
}

/// The pool's `ReplayGuard` is in memory only, so on its own a restart loses every share it
/// has credited and would credit one of them again if a gateway resent it. The ledger it
/// reads back holds their hashes, so the `ReplayGuard` starts from what the pool already credited.
#[test]
fn a_restart_seeds_the_replay_guard_from_the_ledger() {
    let dir = TempDir::new("replay-seed");
    seed(&ledger_path(&dir), 40, 1024);
    // A window wide enough to hold all forty: the `ReplayGuard` is seeded with what the window
    // read back, so a window that trimmed most of them would leave most of them out of the seed.
    let pool = Pool::start(dir, PoolArgs { window_floor: 40 * 1024, ..Default::default() });

    let line = pool.expect_line("ReplayGuard seeded");
    let seeded: usize = line
        .split_whitespace()
        .find_map(|w| w.parse().ok())
        .unwrap_or_else(|| panic!("cannot read the count out of {line:?}"));
    assert_eq!(seeded, 40, "every share the window read back: {line}");
}

/// An empty ledger seeds nothing, so the pool logs nothing. The count is what the window
/// held, not a number it prints regardless.
#[test]
fn an_empty_ledger_seeds_no_hashes() {
    let dir = TempDir::new("replay-seed-empty");
    let pool = Pool::start(dir, PoolArgs { window_floor: 1, ..Default::default() });
    pool.expect_line("listening on");
    assert!(
        !pool.lines().iter().any(|l| l.contains("ReplayGuard seeded")),
        "nothing was read back, so nothing was seeded"
    );
}

/// The ledger inside a data directory is named after the chain the node reports, so a pool
/// moved to another network opens another file rather than this one.
#[test]
fn the_ledger_is_named_after_the_nodes_chain() {
    let node = FakeNode::start();
    let dir = TempDir::new("ledger-name");
    let expected = ledger_path(&dir);
    let pool = Pool::start(dir, PoolArgs { rpc_url: Some(node.url()), ..Default::default() });
    let line = pool.expect_line("share window from");
    assert!(line.contains("regtest.redb"), "{line}");
    assert!(expected.is_file(), "{} should exist", expected.display());
}

/// A ledger stamped for another chain is refused at startup: the pool exits with the reason
/// instead of paying this chain's coinbase to shares found on the other.
#[test]
fn a_ledger_of_another_chain_refuses_to_start() {
    let node = FakeNode::start();
    let dir = TempDir::new("ledger-other-chain");
    // Placed where a regtest pool looks, but stamped as mainnet shares.
    drop(Ledger::open(&ledger_path(&dir), u128::MAX, None, Some("main")).expect("seed"));
    let data_dir = dir.path().display().to_string();
    let output = run_pool(&[
        "--listen",
        "127.0.0.1:0",
        "--data-dir",
        &data_dir,
        "--payout-script",
        "00141111111111111111111111111111111111111111",
        "--rpc",
        &node.url(),
    ]);
    assert!(!output.status.success(), "output:\n{}", printed(&output));
    let text = printed(&output);
    assert!(text.contains("holds shares for chain main"), "{text}");
    assert!(text.contains("the node is on chain regtest"), "{text}");
}

/// `--dump-ledger --data-dir` reads the one ledger in the directory without asking the node
/// which chain named it, and refuses to guess between two.
#[test]
fn dump_ledger_reads_the_one_ledger_in_a_data_dir() {
    let dir = TempDir::new("dump-dir");
    let data_dir = dir.path().display().to_string();
    {
        let (mut l, _) =
            Ledger::open(&ledger_path(&dir), u128::MAX, None, Some("regtest")).expect("seed");
        l.record(now(), "alice", 7, &next_hash()).unwrap();
    }
    let output = run_pool(&["--dump-ledger", "--data-dir", &data_dir]);
    assert!(output.status.success(), "{}", printed(&output));
    let text = printed(&output);
    assert!(text.contains(" 7 alice "), "{text}");

    drop(Ledger::open(&dir.join("main.redb"), u128::MAX, None, Some("main")).expect("second"));
    let output = run_pool(&["--dump-ledger", "--data-dir", &data_dir]);
    assert_eq!(output.status.code(), Some(2), "{}", printed(&output));
    let text = printed(&output);
    assert!(text.contains("more than one ledger") && text.contains("main.redb"), "{text}");
}
