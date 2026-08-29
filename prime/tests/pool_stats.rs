//! The read-only HTTP stats interface (`--stats-listen`). Starts the release binary with the
//! interface enabled and reads it back over HTTP, so the wiring, the JSON snapshot and the
//! served page are all under test.

mod support;

use ratum::datum::messages::{CoinbaserRequest, server_subcmd};
use ratum_prime::ledger::Ledger;
use std::time::{SystemTime, UNIX_EPOCH};
use support::work;
use support::{FakeNode, Pool, PoolArgs, TempDir};

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Seed the ledger with alice (work 3) and bob (work 1), so the window is three parts to one.
fn seed_alice_and_bob(dir: &TempDir) {
    let (mut l, _) = Ledger::open(&dir.join("regtest.redb"), u128::MAX, None, None)
        .expect("open the seed ledger");
    l.record(now(), "alice", 3, &[0x11; 32]).unwrap();
    l.record(now(), "bob", 1, &[0x22; 32]).unwrap();
}

/// The address the pool logs the interface as listening on, e.g. `127.0.0.1:41007`.
fn stats_addr(pool: &Pool) -> String {
    let line = pool.expect_line("stats interface listening on http://");
    line.rsplit("http://").next().expect("an address after http://").trim().to_string()
}

fn get(url: &str) -> (u16, String) {
    let r = minreq::get(url).send().expect("request the stats interface");
    (r.status_code, r.as_str().expect("a utf-8 body").to_string())
}

#[test]
fn the_stats_interface_serves_a_json_snapshot_and_a_page() {
    let node = FakeNode::start();
    node.set_tip(&hex::encode(work::PREV_HASH), 100);
    node.set_difficulty(1.0);
    node.set_coinbase_value(Some(1_000_000));

    let dir = TempDir::new("stats");
    seed_alice_and_bob(&dir);

    let pool = Pool::start(
        dir,
        PoolArgs {
            rpc_url: Some(node.url()),
            window_floor: 4,
            min_payout: 1,
            extra: vec![
                "--stats-listen".into(),
                "127.0.0.1:0".into(),
                "--advertise-address".into(),
                "pool.example.com:29000".into(),
            ],
            ..Default::default()
        },
    );
    let addr = stats_addr(&pool);

    // The JSON snapshot.
    let (code, body) = get(&format!("http://{addr}/stats.json"));
    assert_eq!(code, 200, "stats.json: {body}");
    let s: serde_json::Value = serde_json::from_str(&body).expect("valid json");

    assert_eq!(s["pool"]["fee_bps"], 0);
    assert_eq!(s["pool"]["min_payout"], 1);
    assert_eq!(s["network"]["chain"], "regtest", "the chain the stub node reports");
    assert_eq!(s["connections"]["open"], 0);
    assert_eq!(s["window"]["shares"], 2, "two seeded shares");

    // What a gateway needs to connect: the DATUM port (0, since the test listens on :0), the
    // pool's public key (32-byte sign key plus 32-byte box key, hex, so 128 characters), and
    // the operator-set advertise address the page shows in place of the browser's host.
    // The build: the package version and the git commit build.rs recorded, "unknown" when the
    // source is not a git checkout.
    assert_eq!(s["pool"]["version"], ratum::VERSION);
    assert!(s["pool"]["version"].as_str().expect("a version string").starts_with("0."));

    assert_eq!(s["pool"]["datum_port"], 0);
    assert_eq!(s["pool"]["pubkey"].as_str().expect("a pubkey string").len(), 128);
    assert_eq!(s["pool"]["advertise"], "pool.example.com:29000");

    // The seeded window is three parts alice to one part bob, read from the ledger at startup
    // regardless of the node poll.
    let miners = s["window"]["miners"].as_array().expect("a miners array");
    let alice = miners.iter().find(|m| m["identity"] == "alice").expect("alice is listed");
    let bob = miners.iter().find(|m| m["identity"] == "bob").expect("bob is listed");
    assert!((alice["share_percent"].as_f64().unwrap() - 75.0).abs() < 1e-9);
    assert!((bob["share_percent"].as_f64().unwrap() - 25.0).abs() < 1e-9);
    // Read back from the ledger and not resolved since: the snapshot reads the resolver cache
    // and does not call the node itself, so it reports neither payable nor unpayable.
    assert!(alice["payable"].is_null(), "an identity the pool has not resolved is unknown");

    // The page.
    let (code, body) = get(&format!("http://{addr}/"));
    assert_eq!(code, 200);
    assert!(body.contains("RATUM Prime"), "the page names the pool");
    assert!(body.contains("Connect a gateway"), "the page shows how to connect");
    assert!(body.contains("github.com/iohzrd/ratum"), "the page links to the source repo");

    // An unknown path is a 404, not the page or the snapshot.
    let (code, _) = get(&format!("http://{addr}/nope"));
    assert_eq!(code, 404);
}

/// An identity the node reports as not an address is marked unpayable in the snapshot, so the
/// page does not show a payout it will not receive.
#[test]
fn an_identity_that_cannot_be_paid_is_marked_unpayable() {
    let node = FakeNode::start();
    node.set_tip(&hex::encode(work::PREV_HASH), 100);
    node.set_difficulty(1.0);
    node.set_coinbase_value(Some(1_000_000));
    support::lock(&node.state).invalid_addresses.insert("bob".to_string());

    let dir = TempDir::new("stats-unpayable");
    seed_alice_and_bob(&dir);
    let pool = Pool::start(
        dir,
        PoolArgs {
            rpc_url: Some(node.url()),
            window_floor: 4,
            min_payout: 1,
            extra: vec!["--stats-listen".into(), "127.0.0.1:0".into()],
            ..Default::default()
        },
    );
    let addr = stats_addr(&pool);

    // A coinbaser request resolves every identity in the window, which is what fills the cache
    // the snapshot reads.
    let mut gateway = pool.connect();
    let _config = gateway.recv();
    gateway.send_mining(
        &CoinbaserRequest { value: 1_000_000, prev_hash: node.tip_internal() }.encode(),
    );
    let _ = gateway.recv_until(server_subcmd::COINBASER);

    let (code, body) = get(&format!("http://{addr}/stats.json"));
    assert_eq!(code, 200, "stats.json: {body}");
    let s: serde_json::Value = serde_json::from_str(&body).expect("valid json");
    let miners = s["window"]["miners"].as_array().expect("a miners array");
    let alice = miners.iter().find(|m| m["identity"] == "alice").expect("alice is listed");
    let bob = miners.iter().find(|m| m["identity"] == "bob").expect("bob is listed");

    assert_eq!(alice["payable"], true);
    assert!(alice["unpayable_reason"].is_null());
    assert_eq!(bob["payable"], false, "the node reports bob is not an address");
    assert_eq!(bob["unpayable_reason"], "not a valid address");
    // Bob keeps his work and his share of the window; what the split allocates him is simply
    // not paid to him.
    assert!((bob["share_percent"].as_f64().unwrap() - 25.0).abs() < 1e-9);
}
