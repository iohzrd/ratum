//! A local demo of the stats page, not a test of behavior: seeds a ledger with shares,
//! found blocks and an owed block, starts a stand-in node and the real `ratum-prime`
//! binary with `--stats-listen 127.0.0.1:38080`, keeps one gateway connected, prints the
//! URL, and serves until the process is killed.
//!
//! ```text
//! cargo test --release --test demo_stats -- --ignored --nocapture
//! ```

mod support;

use ratum::datum::messages::{CoinbaserRequest, server_subcmd};
use ratum_prime::ledger::{FoundBlock, Ledger, OwedBlock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use support::{FakeNode, Pool, PoolArgs, TempDir};

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

const COINBASE_VALUE: u64 = 312_500_000;
const MINER_A: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
const MINER_B: &str = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7";
const MINER_C: &str = "tb1q0sqzfp3945rlvxrxka7f5t2xvqzr9jkl2rxq9c";
/// A bare worker name, which the node cannot pay: shown with the unpayable tag once a
/// coinbaser request resolves it.
const MINER_D: &str = "myworker";

/// Shares over the last nine minutes (so the hashrate span covers them), three found
/// blocks (one paid the split in its coinbase, two paid the pool everything), and the owed
/// records for those two (one settled, one not).
fn seed(dir: &TempDir) {
    let (mut l, _) =
        Ledger::open(&dir.join("regtest.redb"), u128::MAX, None, None).expect("open seed ledger");

    // (identity, share difficulty, share count, gateway tag): about 1.45M work, 72% of the
    // 2M window.
    let plan: [(&str, u64, u32, &str); 4] = [
        (MINER_A, 4096, 190, "tn4"),
        (MINER_B, 2048, 210, "garage"),
        (MINER_C, 1024, 155, ""),
        (MINER_D, 1024, 80, "tn4"),
    ];
    let count: u32 = plan.iter().map(|(_, _, n, _)| n).sum();
    let (start, span) = (now() - 540, 530u64);
    let mut i = 0u32;
    for (identity, diff, n, tag) in plan {
        for _ in 0..n {
            let at = start + u64::from(i) * span / u64::from(count);
            let mut hash = [0u8; 32];
            hash[..4].copy_from_slice(&i.to_le_bytes());
            l.record(at, identity, diff, &hash, tag).expect("record share");
            i += 1;
        }
    }

    let block = |n: u8, height, at, paid_to_split, paid_to_pool, cumulative_work| {
        let mut block_hash = [0u8; 32];
        block_hash[4..].copy_from_slice(&[n; 28]);
        FoundBlock {
            at,
            height,
            block_hash,
            paid_to_split,
            paid_to_pool,
            finder: MINER_A.to_string(),
            tag: "DATUM User".to_string(),
            difficulty: 1_000_000.0,
            cumulative_work,
        }
    };
    let t = now();
    let b1 = block(0x1a, 151_422, t - 400_000, 298_000_000, 14_500_000, 1_100_000);
    let b2 = block(0x2b, 151_800, t - 200_000, 0, COINBASE_VALUE, 2_020_000);
    let b3 = block(0x3c, 152_102, t - 86_400, 0, COINBASE_VALUE, 2_940_000);
    for b in [&b1, &b2, &b3] {
        l.record_block(b.clone()).expect("record block");
    }
    // The two blocks whose coinbase paid the window nothing; the older one is settled.
    for (b, settled_at) in [(&b2, Some(t - 100_000)), (&b3, None)] {
        l.record_owed(OwedBlock {
            at: b.at,
            height: b.height,
            block_hash: b.block_hash,
            total: COINBASE_VALUE,
            settled_at,
            entries: vec![
                (MINER_A.to_string(), 169_375_000),
                (MINER_B.to_string(), 93_125_000),
                (MINER_C.to_string(), 50_000_000),
            ],
        })
        .expect("record owed");
    }
}

#[test]
#[ignore = "a demo server, not a test: serves the stats page until the process is killed"]
fn serve_the_stats_page_with_demo_data() {
    let node = FakeNode::start();
    node.set_tip(&("00000000000000000002".to_string() + &"8c".repeat(22)), 152_344);
    node.set_difficulty(1_000_000.0);
    node.set_coinbase_value(Some(COINBASE_VALUE));
    support::lock(&node.state).invalid_addresses.insert(MINER_D.to_string());

    let dir = TempDir::new("stats-demo");
    seed(&dir);

    let pool = Pool::start(
        dir,
        PoolArgs {
            rpc_url: Some(node.url()),
            window_multiple: 2.0,
            min_difficulty: 1024,
            min_payout: 546,
            motd: "local demo: seeded shares, stand-in node".to_string(),
            extra: vec!["--stats-listen".into(), "127.0.0.1:38080".into()],
            ..Default::default()
        },
    );
    let line = pool.expect_line("stats interface listening on http://");
    let addr = line.rsplit("http://").next().expect("an address after http://").trim().to_string();

    // One connected gateway: its coinbaser request resolves the window's identities (which
    // is what marks the bare worker name unpayable on the page), repeated to keep the
    // resolver cache and the connection alive.
    let mut gateway = pool.connect();
    let _config = gateway.recv();
    let prev_hash = node.tip_internal();
    std::thread::spawn(move || {
        loop {
            gateway.send_mining(&CoinbaserRequest { value: COINBASE_VALUE, prev_hash }.encode());
            let _ = gateway.recv_until(server_subcmd::COINBASER);
            std::thread::sleep(Duration::from_secs(30));
        }
    });

    println!("stats page: http://{addr}/");
    println!("serving until this process is killed");
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}
