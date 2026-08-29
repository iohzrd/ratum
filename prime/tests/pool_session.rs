//! What a gateway receives from `ratum-prime`.
//!
//! Every test here starts the release binary and sends it wire-protocol frames, so
//! argument parsing, the connection loop, the share ledger and the node calls are all
//! under test, not a re-implementation of them.

mod support;

use ratum::datum::messages::{
    ClientConfig, CoinbaseOutput, CoinbaserRequest, CoinbaserResponse, RejectReason, ShareResponse,
    ShareVerdict, client_subcmd, server_subcmd,
};
use ratum::datum::share::PowSubmit;
use ratum::target;
use ratum_prime::ledger::Ledger;
use ratum_prime::verify::TIP_GRACE_SECS;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use support::work::{self, Tagging, Work};
use support::{FakeNode, Pool, PoolArgs, TempDir, script_for_address};

fn now() -> u32 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()) as u32
}

/// Seed a data directory's ledger with alice (one share of difficulty 3) and bob (one share of
/// difficulty 1), so a split of it pays them three to one.
fn seed_alice_and_bob(dir: &TempDir) {
    let (mut l, _) = Ledger::open(&dir.join("regtest.redb"), u128::MAX, None, None)
        .expect("open the seed ledger");
    l.record(now() as u64, "alice", 3, &[0x11; 32]).unwrap();
    l.record(now() as u64, "bob", 1, &[0x22; 32]).unwrap();
}

fn tagging() -> Tagging<'static> {
    Tagging { tag: "RATUM", prime_id: 1, headline: None }
}

/// Work whose coinbase pays everything to the pool's own script: with an empty share window
/// the pool dictates no outputs, and the gateway pays the whole value to the pool's payout
/// script.
fn work_for(pool_payout: &[u8]) -> Work {
    Work::build(&tagging(), pool_payout, &[], work::COINBASE_VALUE)
}

fn pool_payout_script() -> Vec<u8> {
    script_for_address("pool")
}

fn submit_and_read(gateway: &mut support::Gateway, s: &PowSubmit) -> ShareResponse {
    gateway.send_mining(&s.encode());
    let (payload, _) = gateway.recv_until(server_subcmd::SHARE_RESPONSE);
    ShareResponse::decode(&payload).expect("share response decodes")
}

fn reason(response: &ShareResponse) -> RejectReason {
    match response.verdict {
        ShareVerdict::Rejected(r) => r,
        other => panic!("expected a rejection, got {other:?}"),
    }
}

#[test]
fn the_handshake_carries_the_motd_and_the_configured_policy() {
    let pool = Pool::start(
        TempDir::new("config"),
        PoolArgs {
            motd: "a pool for the hardfork".to_string(),
            coinbase_tag: "TAGGED".to_string(),
            prime_id: 0x0102_0304,
            min_difficulty: 16384,
            ..Default::default()
        },
    );
    let mut gateway = pool.connect();
    assert_eq!(gateway.motd(), "a pool for the hardfork");

    let (header, payload) = gateway.recv();
    assert!(header.is_signed, "the config message is signed");
    assert!(header.is_encrypted_channel);
    let config = ClientConfig::decode(&payload).expect("config decodes");
    assert_eq!(config.payout_script, pool_payout_script());
    assert_eq!(config.coinbase_tag, "TAGGED");
    assert_eq!(config.prime_id, 0x0102_0304);
    assert_eq!(config.min_difficulty, 16384);
}

#[test]
fn a_second_gateway_gets_its_own_session() {
    let pool = Pool::simple("two-gateways");
    let mut first = pool.connect();
    let mut second = pool.connect();
    for gateway in [&mut first, &mut second] {
        let (_, payload) = gateway.recv();
        assert_eq!(payload.first(), Some(&server_subcmd::CONFIG));
    }
    pool.expect_line("connected");
}

#[test]
fn connections_past_the_limit_are_refused() {
    let pool = Pool::start(
        TempDir::new("limit"),
        PoolArgs { max_connections: Some(1), ..Default::default() },
    );
    let mut first = pool.connect();
    let (_, payload) = first.recv();
    assert_eq!(payload.first(), Some(&server_subcmd::CONFIG));

    let extra = std::net::TcpStream::connect(pool.addr).expect("connect");
    pool.expect_line("refused: already serving 1 connections");
    drop(extra);
}

#[test]
fn an_empty_window_dictates_no_outputs() {
    let node = FakeNode::start();
    let pool = Pool::start(
        TempDir::new("coinbaser-empty-window"),
        PoolArgs { rpc_url: Some(node.url()), ..Default::default() },
    );
    let mut gateway = pool.connect();
    let _config = gateway.recv();

    let request = CoinbaserRequest { value: work::COINBASE_VALUE, prev_hash: node.tip_internal() };
    gateway.send_mining(&request.encode());

    let (payload, _) = gateway.recv_until(server_subcmd::COINBASER);
    let response = CoinbaserResponse::decode(&payload).expect("coinbaser response");
    assert!(
        response.outputs.is_empty(),
        "no share has been credited, so no output is dictated: {response:?}"
    );
    pool.expect_line("paying 0 miners");
}

#[test]
fn a_split_pays_the_miners_in_the_window_by_work() {
    let node = FakeNode::start();
    node.set_difficulty(1.0);
    support::lock(&node.state).coinbase_value = Some(1_000_000);
    let dir = TempDir::new("coinbaser-split");
    seed_alice_and_bob(&dir);

    let pool = Pool::start(
        dir,
        PoolArgs {
            rpc_url: Some(node.url()),
            window_floor: 4,
            min_payout: 1,
            ..Default::default()
        },
    );
    pool.expect_line("share window from");

    let mut gateway = pool.connect();
    let _config = gateway.recv();
    let request = CoinbaserRequest { value: 1_000_000, prev_hash: node.tip_internal() };
    gateway.send_mining(&request.encode());

    let (payload, _) = gateway.recv_until(server_subcmd::COINBASER);
    let response = CoinbaserResponse::decode(&payload).expect("coinbaser response");
    let paid: Vec<(u64, Vec<u8>)> =
        response.outputs.iter().map(|o| (o.value, o.script.clone())).collect();
    assert_eq!(
        paid,
        vec![(750_000, script_for_address("alice")), (250_000, script_for_address("bob")),],
        "three quarters of the work is alice's"
    );
    assert!(node.called("validateaddress") >= 2, "the node resolved both addresses");
}

#[test]
fn a_fee_is_deducted_from_the_split_and_left_to_the_pool() {
    let node = FakeNode::start();
    node.set_difficulty(1.0);
    support::lock(&node.state).coinbase_value = Some(1_000_000);
    let dir = TempDir::new("coinbaser-fee");
    seed_alice_and_bob(&dir);

    // 100 bps is 1%, the maximum fee: 10_000 of 1_000_000 is deducted before the split, and
    // 990_000 is split three to one. The gateway pays the 10_000 remainder to the pool's
    // payout script.
    let pool = Pool::start(
        dir,
        PoolArgs {
            rpc_url: Some(node.url()),
            window_floor: 4,
            min_payout: 1,
            extra: vec!["--fee-bps".into(), "100".into()],
            ..Default::default()
        },
    );
    pool.expect_line("operator fee 100 bps");

    let mut gateway = pool.connect();
    let _config = gateway.recv();
    let request = CoinbaserRequest { value: 1_000_000, prev_hash: node.tip_internal() };
    gateway.send_mining(&request.encode());

    let (payload, _) = gateway.recv_until(server_subcmd::COINBASER);
    let response = CoinbaserResponse::decode(&payload).expect("coinbaser response");
    let paid: Vec<(u64, Vec<u8>)> =
        response.outputs.iter().map(|o| (o.value, o.script.clone())).collect();
    assert_eq!(
        paid,
        vec![(742_500, script_for_address("alice")), (247_500, script_for_address("bob")),],
        "three quarters of the value after the fee is alice's"
    );
    let split_total: u64 = response.outputs.iter().map(|o| o.value).sum();
    assert_eq!(split_total, 990_000, "the split is the value minus the 1% fee");
    // The response carries the full value; the difference is the remainder the gateway pays
    // to the pool's payout script.
    assert_eq!(response.value - split_total, 10_000, "the pool keeps the fee");
}

#[test]
fn an_address_the_node_rejects_removes_only_that_miner_from_the_split() {
    let node = FakeNode::start();
    support::lock(&node.state).invalid_addresses.insert("bob".to_string());
    support::lock(&node.state).coinbase_value = Some(1_000_000);
    let dir = TempDir::new("coinbaser-bad-address");
    seed_alice_and_bob(&dir);

    let pool = Pool::start(
        dir,
        PoolArgs { rpc_url: Some(node.url()), window_floor: 4, ..Default::default() },
    );
    let mut gateway = pool.connect();
    let _config = gateway.recv();
    gateway.send_mining(
        &CoinbaserRequest { value: 1_000_000, prev_hash: node.tip_internal() }.encode(),
    );

    let (payload, _) = gateway.recv_until(server_subcmd::COINBASER);
    let response = CoinbaserResponse::decode(&payload).expect("coinbaser response");
    assert_eq!(response.outputs.len(), 1, "alice is still paid: {response:?}");
    assert_eq!(response.outputs[0].script, script_for_address("alice"));
    pool.expect_line("cannot be paid: not a valid address");
}

#[test]
fn a_coinbase_value_the_node_does_not_recognize_is_refused() {
    let node = FakeNode::start();
    support::lock(&node.state).coinbase_value = Some(312_500_000);
    let pool = Pool::start(
        TempDir::new("coinbaser-value"),
        PoolArgs { rpc_url: Some(node.url()), ..Default::default() },
    );
    pool.expect_line("node template: the next coinbase may pay");

    let mut gateway = pool.connect();
    let _config = gateway.recv();
    gateway.send_mining(
        &CoinbaserRequest { value: 2_100_000_000_000_000, prev_hash: node.tip_internal() }.encode(),
    );

    pool.expect_line("refusing a split");
    assert!(
        gateway.received_no(server_subcmd::COINBASER, Duration::from_millis(500)),
        "a split was sent for a value the node does not recognize"
    );
}

#[test]
fn a_new_tip_is_announced_to_the_gateway() {
    let node = FakeNode::start();
    let pool = Pool::start(
        TempDir::new("blocknotify"),
        PoolArgs { rpc_url: Some(node.url()), ..Default::default() },
    );
    let mut gateway = pool.connect();
    let (_, payload) = gateway.recv();
    assert_eq!(payload.first(), Some(&server_subcmd::CONFIG));

    let (payload, _) = gateway.recv_until(server_subcmd::BLOCKNOTIFY);
    assert_eq!(payload, vec![server_subcmd::BLOCKNOTIFY]);

    node.set_tip(&("ab".repeat(31) + "cd"), 101);
    let (payload, _) = gateway.recv_until(server_subcmd::BLOCKNOTIFY);
    assert_eq!(payload, vec![server_subcmd::BLOCKNOTIFY]);
}

/// The verifier's network target must be set again when the node's template arrives after the
/// tip it belongs to. If the first getblocktemplate at a new tip fails, the watcher publishes
/// that tip with no target; a later poll fills the target in without the tip hash changing. A
/// session that first observed the tip during the failure must receive the target on the later
/// poll, rather than holding a null target for the whole tip.
///
/// The observable used here is the on-tip check that rejects a job whose bits are easier than
/// the node's next block: it runs only when the target is set, and it returns `BadTarget`
/// in `rebuild` before any proof-of-work check, so it needs no real mining. With the target
/// null (the target not set again) the check is skipped and the same share is refused as a
/// high hash instead.
#[test]
fn the_network_target_is_set_again_when_the_template_arrives_after_its_tip() {
    let node = FakeNode::start();
    // The node's next block is at a hard target; a job on the tip claiming the easy bits is
    // then easier than the node and must be rejected, but only while the target is set.
    node.set_next_bits(&format!("{:08x}", u32::from_le_bytes(work::HARD_NBITS)));
    let pool = Pool::start(
        TempDir::new("late-template"),
        PoolArgs { rpc_url: Some(node.url()), ..Default::default() },
    );
    pool.expect_line("node template: the next coinbase may pay");

    let mut gateway = pool.connect();
    let (_, payload) = gateway.recv();
    assert_eq!(payload.first(), Some(&server_subcmd::CONFIG));
    // The blocknotify for the startup tip.
    gateway.recv_until(server_subcmd::BLOCKNOTIFY);

    // A new tip arrives while the node cannot serve a template: the watcher publishes the tip
    // with no target, and the session observes it holding a null target for it.
    node.set_coinbase_value(None);
    node.set_tip(&("ab".repeat(31) + "cd"), 101);
    pool.expect_line("could not read a template");
    gateway.recv_until(server_subcmd::BLOCKNOTIFY);

    // The node recovers and serves a template for the same tip, without the tip hash changing.
    // A distinct coinbase value gives a log line the startup poll does not match, so the wait
    // synchronizes on this poll rather than the earlier success.
    node.set_coinbase_value(Some(250_000_000));
    pool.expect_line("pay 250000000 sats");
    // Let the session's loop cycle once (past IDLE_POLL) so it sets the target before the
    // share arrives.
    std::thread::sleep(Duration::from_millis(300));

    // A share whose job is on the recovered tip and claims the easy bits: rejected as BadTarget
    // once the target is set again. Without that the target is null, the check is skipped,
    // and the same share is refused as a high hash instead.
    let mut work = work_for(&pool_payout_script());
    work.job.prev_hash = node.tip_internal();
    work.job.nbits = work::EASY_NBITS;
    let share = work.submit("miner.rig", now(), 0, 0);
    let response = submit_and_read(&mut gateway, &share);
    assert_eq!(
        reason(&response),
        RejectReason::BadTarget,
        "an on-tip job with easy bits is rejected only while the network target is set"
    );
}

#[test]
fn a_share_that_misses_the_target_is_rejected_as_a_high_hash() {
    let pool = Pool::simple("high-hash");
    let mut gateway = pool.connect();
    let _config = gateway.recv();

    let work = work_for(&pool_payout_script());
    let share = work.submit("miner.rig", now(), 0, 0);
    let response = submit_and_read(&mut gateway, &share);
    assert_eq!(reason(&response), RejectReason::HighHash);
    assert_eq!(response.nonce, share.nonce);
    assert_eq!(response.job_id, share.job_id);
    assert!(pool.ledger_lines().is_empty(), "a rejected share is not credited");
}

#[test]
fn eight_reasons_a_share_is_rejected() {
    let pool = Pool::start(
        TempDir::new("reject-reasons"),
        PoolArgs { min_difficulty: 16384, ..Default::default() },
    );
    let mut gateway = pool.connect();
    let _config = gateway.recv();

    let payout = pool_payout_script();
    let work = work_for(&payout);
    let target_byte = 14; // 2^14 = the pool's minimum

    let mut under_minimum = work.submit("miner.rig", now(), 0, 0);
    under_minimum.target_byte = 0;
    assert_eq!(reason(&submit_and_read(&mut gateway, &under_minimum)), RejectReason::BadTarget);

    let mut bad_name = work.submit("has a space", now(), 0, target_byte);
    bad_name.job_id = 1;
    assert_eq!(reason(&submit_and_read(&mut gateway, &bad_name)), RejectReason::BadUsername);

    let mut old = work.submit("miner.rig", now() - 3 * 60 * 60, 0, target_byte);
    old.job_id = 2;
    assert_eq!(reason(&submit_and_read(&mut gateway, &old)), RejectReason::BadNtime);

    let mut unknown_job = work.submit("miner.rig", now(), 0, target_byte);
    unknown_job.job_id = 9;
    unknown_job.job = None;
    unknown_job.coinbase = None;
    assert_eq!(reason(&submit_and_read(&mut gateway, &unknown_job)), RejectReason::BadJobId);

    let other_pool = Work::build(
        &Tagging { tag: "SOMEONE ELSE", prime_id: 1, headline: None },
        &payout,
        &[],
        work::COINBASE_VALUE,
    );
    let mut other_pools_tag = other_pool.submit("miner.rig", now(), 0, target_byte);
    other_pools_tag.job_id = 3;
    assert_eq!(
        reason(&submit_and_read(&mut gateway, &other_pools_tag)),
        RejectReason::MissingPoolTag
    );

    let elsewhere = Work::build(
        &tagging(),
        &payout,
        &[CoinbaseOutput { value: 1_000_000, script: work::p2wpkh(0x77) }],
        work::COINBASE_VALUE,
    );
    let mut undictated_output = elsewhere.submit("miner.rig", now(), 0, target_byte);
    undictated_output.job_id = 4;
    assert_eq!(
        reason(&submit_and_read(&mut gateway, &undictated_output)),
        RejectReason::BadCoinbaseOutputs,
        "the pool did not dictate that output"
    );

    let mut no_coinbase = work.submit("miner.rig", now(), 0, target_byte);
    no_coinbase.job_id = 5;
    no_coinbase.coinbase = None;
    assert_eq!(reason(&submit_and_read(&mut gateway, &no_coinbase)), RejectReason::CoinbaseMissing);

    let mut wrong_id = work.submit("miner.rig", now(), 0, target_byte);
    wrong_id.job_id = 6;
    wrong_id.coinbase_id = 3;
    assert_eq!(reason(&submit_and_read(&mut gateway, &wrong_id)), RejectReason::CoinbaseIdMismatch);
}

#[test]
fn work_on_a_prev_hash_that_is_not_the_node_tip_is_stale() {
    let node = FakeNode::start();
    node.set_tip(&("77".repeat(32)), 500);
    // The node's next block is at a target no test share meets, so the share is not a block
    // and the staleness of its off-tip job determines the verdict. Whether a share is a block
    // is determined by this template target, not from the job's own bits.
    node.set_next_bits(&format!("{:08x}", u32::from_le_bytes(work::HARD_NBITS)));
    let pool = Pool::start(
        TempDir::new("stale"),
        PoolArgs { rpc_url: Some(node.url()), ..Default::default() },
    );
    pool.expect_line("node tip: height 500");

    let mut gateway = pool.connect();
    let _config = gateway.recv();
    let work = work_for(&pool_payout_script()); // prev_hash is 0x5a…, not the node's tip
    let share = work.submit("miner.rig", now(), 0, 0);
    assert_eq!(reason(&submit_and_read(&mut gateway, &share)), RejectReason::StaleBlock);
}

/// Sets the node's tip, then replaces it, and returns a gateway whose verifier has received
/// both changes: the connection sends a blocknotify immediately after it calls `set_tip`, so
/// receiving one is proof the tip the share is checked against has changed.
fn pool_past_the_tip(dir: &str, tips: &[&str]) -> (support::FakeNode, Pool, support::Gateway) {
    let node = FakeNode::start();
    node.set_tip(&"5a".repeat(32), 100); // the prev_hash work_for builds on
    // The node's next block is at a target no test share meets, so a share on an off-tip job is
    // not a block and the staleness of its off-tip job determines the verdict. Whether a share is a
    // block is determined by this template target, not from a job's own bits.
    node.set_next_bits(&format!("{:08x}", u32::from_le_bytes(work::HARD_NBITS)));
    let pool = Pool::start(
        TempDir::new(dir),
        PoolArgs { rpc_url: Some(node.url()), ..Default::default() },
    );
    pool.expect_line("node tip: height 100");

    let mut gateway = pool.connect();
    let _config = gateway.recv();
    gateway.recv_until(server_subcmd::BLOCKNOTIFY);

    for (i, tip) in tips.iter().enumerate() {
        node.set_tip(tip, 101 + i as u32);
        pool.expect_line(&format!("node tip: height {}", 101 + i));
        gateway.recv_until(server_subcmd::BLOCKNOTIFY);
    }
    (node, pool, gateway)
}

/// A share that is not a block, so the staleness check applies to it (a block is exempt). The
/// node's next block (set in `pool_past_the_tip`) is at a target this share does
/// not meet, and it does not meet the share target either, so what is asserted is only which
/// rejection comes back.
fn off_tip_share() -> PowSubmit {
    let work = work_for(&pool_payout_script());
    work.submit("miner.rig", now(), 0, 0)
}

#[test]
fn work_on_the_most_recently_replaced_tip_is_not_refused_as_stale() {
    // The miner was hashing this job when the tip changed and had no signal to stop.
    let (_node, _pool, mut gateway) = pool_past_the_tip("grace-fresh", &["77".repeat(32).as_str()]);
    let reply = submit_and_read(&mut gateway, &off_tip_share());
    assert!(
        !matches!(reply.verdict, ShareVerdict::Rejected(RejectReason::StaleBlock)),
        "within the grace period the job is still checked, got {:?}",
        reply.verdict
    );
}

#[test]
fn work_on_a_replaced_tip_goes_stale_once_the_grace_period_ends() {
    let (_node, _pool, mut gateway) =
        pool_past_the_tip("grace-expired", &["77".repeat(32).as_str()]);
    std::thread::sleep(Duration::from_millis(TIP_GRACE_SECS * 1000 + 1500));
    let reply = submit_and_read(&mut gateway, &off_tip_share());
    assert_eq!(
        reply.verdict,
        ShareVerdict::Rejected(RejectReason::StaleBlock),
        "past the grace period the job is stale"
    );
}

#[test]
fn the_grace_period_is_not_ended_by_further_tip_changes() {
    // The tip can change several times within the grace period. Work on the first replaced tip
    // is still evaluated, however many changes follow.
    let (_node, _pool, mut gateway) = pool_past_the_tip(
        "grace-tip-changes",
        &["77".repeat(32).as_str(), "88".repeat(32).as_str(), "99".repeat(32).as_str()],
    );
    let reply = submit_and_read(&mut gateway, &off_tip_share());
    assert!(
        !matches!(reply.verdict, ShareVerdict::Rejected(RejectReason::StaleBlock)),
        "the parent left the tip once, not three times, got {:?}",
        reply.verdict
    );
}

/// The share that finds a block reaches the pool after the block itself does, because
/// the gateway submits the block to its node before forwarding the share, so by then the
/// node's tip is no longer the job's prev_hash. The gateway sends it regardless
/// (`datum_stratum.c` tests the block target before `is_stale_prevblock`), as does p2pool
/// (`work.py` calls `helper.submit_block` as soon as `pow_hash <= header['bits'].target`, before
/// it computes `on_time` at all), so the pool has to take it.
#[test]
fn work_on_an_off_tip_job_is_not_refused_as_stale_when_it_meets_the_network_target() {
    let node = FakeNode::start();
    node.set_tip(&("77".repeat(32)), 500);
    let pool = Pool::start(
        TempDir::new("stale-block"),
        PoolArgs { rpc_url: Some(node.url()), ..Default::default() },
    );
    pool.expect_line("node tip: height 500");

    let mut gateway = pool.connect();
    let _config = gateway.recv();
    let work = work_for(&pool_payout_script()); // prev_hash is 0x5a…, not the node's tip

    // The default nbits is regtest's proof-of-work limit (powLimit), whose target is
    // 0x7fffff…, so only about half of all hashes meet it. Step the time until this share is
    // one that does, rather than testing whichever hash the clock happened to produce.
    let network = target::bits_to_target(u32::from_le_bytes(work::EASY_NBITS))
        .expect("the easy nbits names a target");
    let base = now();
    let ntime = (0..64)
        .map(|offset| base + offset)
        .find(|&t| target::meets_target(&work.hash(t, 0, 0), &network))
        .expect("a time whose share meets the network target within 64 tries");

    let share = work.submit("miner.rig", ntime, 0, 0);
    let reply = submit_and_read(&mut gateway, &share);
    assert!(
        !matches!(reply.verdict, ShareVerdict::Rejected(RejectReason::StaleBlock)),
        "a share meeting the network target is not rejected for the tip having changed, got {:?}",
        reply.verdict
    );
}

#[test]
fn a_share_that_does_not_decode_receives_a_response() {
    let pool = Pool::simple("malformed");
    let mut gateway = pool.connect();
    let _config = gateway.recv();

    gateway.send_mining(&[client_subcmd::SUBMIT_POW, 0x01, 0x02]);
    let (payload, _) = gateway.recv_until(server_subcmd::SHARE_RESPONSE);
    let response = ShareResponse::decode(&payload).expect("share response");
    assert!(matches!(response.verdict, ShareVerdict::Rejected(_)));
    pool.expect_line("could not decode share");

    // The session continues: the next message is still responded to.
    gateway.send_mining(
        &CoinbaserRequest { value: work::COINBASE_VALUE, prev_hash: work::PREV_HASH }.encode(),
    );
    let (payload, _) = gateway.recv_until(server_subcmd::COINBASER);
    assert_eq!(payload.first(), Some(&server_subcmd::COINBASER));
}

#[test]
fn an_extranonce_of_the_wrong_size_names_its_own_reason() {
    let pool = Pool::simple("extranonce");
    let mut gateway = pool.connect();
    let _config = gateway.recv();

    let work = work_for(&pool_payout_script());
    let mut share = work.submit("miner.rig", now(), 0, 0);
    share.extranonce = vec![0u8; 8];
    let mut bytes = share.encode();
    // The length byte is at offset 17: after the command byte, job id, coinbase id, flags,
    // target byte, ntime, nonce and version.
    bytes[17] = 8;
    gateway.send_mining(&bytes);
    let (payload, _) = gateway.recv_until(server_subcmd::SHARE_RESPONSE);
    let response = ShareResponse::decode(&payload).expect("share response");
    assert_eq!(reason(&response), RejectReason::BadExtranonceSize);
}

#[test]
fn nothing_but_a_mining_command_is_acted_on() {
    let pool = Pool::simple("other-commands");
    let mut gateway = pool.connect();
    let _config = gateway.recv();

    gateway.send(ratum::datum::framing::cmd::INFO, b"hello\0");
    // A blocknotify arrives on the pool's own schedule; nothing responds to the INFO itself.
    assert!(gateway.received_no(server_subcmd::SHARE_RESPONSE, Duration::from_millis(300)));

    gateway.send_mining(
        &CoinbaserRequest { value: work::COINBASE_VALUE, prev_hash: work::PREV_HASH }.encode(),
    );
    let (payload, _) = gateway.recv_until(server_subcmd::COINBASER);
    assert_eq!(payload.first(), Some(&server_subcmd::COINBASER));
}
