//! The cases that need a real proof of work: a share the pool accepts, credits, refuses
//! to credit twice, and turns into a block it relays to its node.
//!
//! Finding a BLAKE2b hash under the difficulty-1 target takes about 2^32 attempts, so these
//! are ignored by default:
//!
//! ```text
//! cargo test --release --test pool_block -- --ignored --test-threads 1
//! ```

mod support;

use ratum::bitcoin;
use ratum::datum::messages::{RejectReason, ShareResponse, ShareVerdict, server_subcmd};
use ratum::datum::share::PowSubmit;
use ratum::datum::validation::{self, Status, TxnBundle};
use ratum::target;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use support::work::{self, Tagging, Work};
use support::{FakeNode, Gateway, Pool, PoolArgs, TempDir, script_for_address};

/// The bytes of a serialized version 2 header.
const HEADER: usize = ratum::header::HEADER_V2_SIZE;
// Difficulty 1, the smallest the test pool accepts (`PoolArgs` defaults to `--min-diff 1`).
const TARGET_BYTE: u8 = 0;
const USERNAME: &str = "alice.rig1";

fn pool_payout_script() -> Vec<u8> {
    script_for_address("pool")
}

/// A transaction the pool's txid parser accepts: one input, one output, no witness.
fn simple_tx(tag: u8) -> Vec<u8> {
    let mut tx = vec![0x02, 0x00, 0x00, 0x00];
    tx.push(0x01);
    tx.extend_from_slice(&[tag; 32]);
    tx.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    tx.push(0x01);
    tx.push(0x51);
    tx.extend_from_slice(&[0xff; 4]);
    tx.push(0x01);
    tx.extend_from_slice(&1_000u64.to_le_bytes());
    tx.push(0x02);
    tx.extend_from_slice(&[0x00, tag]);
    tx.extend_from_slice(&[0x00; 4]);
    tx
}

/// Work with two other transactions in the block, and the merkle branch that commits to
/// them: for three leaves the branch is the second transaction, then the third paired with
/// itself.
fn work_with_transactions() -> (Work, Vec<Vec<u8>>) {
    let txns = vec![simple_tx(0xa1), simple_tx(0xb2)];
    let a = bitcoin::txid(&txns[0]).expect("txid a");
    let b = bitcoin::txid(&txns[1]).expect("txid b");
    let mut paired = [0u8; 64];
    paired[..32].copy_from_slice(&b);
    paired[32..].copy_from_slice(&b);

    let mut w = Work::build(
        &Tagging { tag: "RATUM", prime_id: 1, headline: None },
        &pool_payout_script(),
        &[],
        work::COINBASE_VALUE,
    );
    w.job.merkle_branches = vec![a, bitcoin::sha256d(&paired)];
    w.job.txn_count = txns.len() as u32;
    (w, txns)
}

/// One found nonce, shared by every test in this file: the search takes most of the time,
/// and the work it solves is the same each time.
fn solved() -> &'static (u32, u32) {
    static SOLVED: OnceLock<(u32, u32)> = OnceLock::new();
    SOLVED.get_or_init(|| {
        let (w, _) = work_with_transactions();
        let ntime = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()) as u32;
        find_nonce_with_retries(&w, ntime)
    })
}

/// A single pass over the nonce space finds a difficulty-1 hash with probability about 0.63
/// (1 - 1/e), so give the search several timestamps to work with before calling it a failure.
fn find_nonce_with_retries(w: &Work, from: u32) -> (u32, u32) {
    let target = target::target_for_pot(TARGET_BYTE);
    for offset in 0..8u32 {
        if let Some(nonce) = w.find_nonce(from + offset, TARGET_BYTE, &target) {
            return (from + offset, nonce);
        }
    }
    panic!("no nonce met difficulty 1 in eight passes over the nonce space");
}

fn solved_share(w: &Work, is_block: bool) -> PowSubmit {
    let (ntime, nonce) = *solved();
    let mut share = w.submit(USERNAME, ntime, nonce, TARGET_BYTE);
    share.is_block = is_block;
    share
}

fn started(dir: &str, node: &FakeNode) -> Pool {
    // The pool refuses work built on anything but the node's tip, and the work's previous
    // block is 0x5a repeated, which is the same in either byte order.
    node.set_tip(&"5a".repeat(32), 840_000);
    support::lock(&node.state).coinbase_value = Some(work::COINBASE_VALUE);
    Pool::start(
        TempDir::new(dir),
        PoolArgs { rpc_url: Some(node.url()), min_payout: 1, ..Default::default() },
    )
}

fn ready(pool: &Pool) -> Gateway {
    let mut gateway = pool.connect();
    let (_, config) = gateway.recv();
    assert_eq!(config.first(), Some(&server_subcmd::CONFIG));
    gateway
}

fn submit(gateway: &mut Gateway, share: &PowSubmit) -> ShareResponse {
    gateway.send_mining(&share.encode());
    let (payload, _) = gateway.recv_until(server_subcmd::SHARE_RESPONSE);
    ShareResponse::decode(&payload).expect("share response")
}

#[test]
#[ignore = "searches ~2^32 hashes; run with --release -- --ignored"]
fn a_solved_share_is_accepted_and_written_to_the_ledger() {
    let node = FakeNode::start();
    let pool = started("accept", &node);
    let mut gateway = ready(&pool);

    let (w, _) = work_with_transactions();
    let share = solved_share(&w, false);
    let response = submit(&mut gateway, &share);
    assert_eq!(response.verdict, ShareVerdict::Accepted, "{response:?}");
    assert_eq!(response.nonce, share.nonce);
    assert_eq!(response.target_byte, TARGET_BYTE);

    let ledger = pool.ledger_lines();
    assert_eq!(ledger.len(), 1, "one share, one line: {ledger:?}");
    let fields: Vec<&str> = ledger[0].split_whitespace().collect();
    assert_eq!(fields.len(), 4, "at, difficulty, identity, hash: {:?}", ledger[0]);
    assert_eq!(fields[1], "1", "difficulty 1");
    assert_eq!(fields[2], "alice", "the worker name is not part of the identity");
    let hash = w.hash(share.ntime, share.nonce, TARGET_BYTE);
    assert_eq!(fields[3], hex::encode(hash), "the line records the work itself");
}

#[test]
#[ignore = "searches ~2^32 hashes; run with --release -- --ignored"]
fn the_same_work_is_never_credited_twice() {
    let node = FakeNode::start();
    let pool = started("replay", &node);
    let (w, _) = work_with_transactions();
    let share = solved_share(&w, false);

    let mut first = ready(&pool);
    assert_eq!(submit(&mut first, &share).verdict, ShareVerdict::Accepted);
    assert_eq!(
        submit(&mut first, &share).verdict,
        ShareVerdict::Rejected(RejectReason::DuplicateWork),
        "the same share twice on one connection"
    );

    // A second gateway cannot claim it either: the `ReplayGuard` is shared.
    let mut second = ready(&pool);
    assert_eq!(
        submit(&mut second, &share).verdict,
        ShareVerdict::Rejected(RejectReason::DuplicateWork),
        "the same share from another connection"
    );
    assert_eq!(pool.ledger_lines().len(), 1, "only the first was credited");
}

#[test]
#[ignore = "searches ~2^32 hashes; run with --release -- --ignored"]
fn a_block_with_no_other_transactions_is_relayed_at_once() {
    let node = FakeNode::start();
    let pool = started("relay-empty", &node);
    let mut gateway = ready(&pool);

    let (mut w, _) = work_with_transactions();
    w.job.merkle_branches.clear();
    w.job.txn_count = 0;
    let (from, _) = *solved();
    let (ntime, nonce) = find_nonce_with_retries(&w, from);
    let mut share = w.submit(USERNAME, ntime, nonce, TARGET_BYTE);
    share.is_block = true;

    assert_eq!(submit(&mut gateway, &share).verdict, ShareVerdict::Accepted);
    let block = node.wait_for_submission(Duration::from_secs(10)).expect("the block was relayed");
    let raw = hex::decode(block).expect("block hex");

    let header = w.header(ntime, nonce, TARGET_BYTE).serialize();
    assert_eq!(&raw[..HEADER], &header, "the block carries the header the pool verified");
    assert_eq!(raw[HEADER], 1, "one transaction: the coinbase");
    assert_eq!(&raw[HEADER + 1..], &w.full_coinbase(TARGET_BYTE)[..]);
    pool.expect_line("BLOCK at height 840000");
}

/// A share whose identity the node reports as not an address is rejected as `BadUsername`
/// and not credited, but the block it solved is still relayed: the block pays the outputs the
/// coinbaser dictated, which is independent of who submitted it.
#[test]
#[ignore = "searches ~2^32 hashes; run with --release -- --ignored"]
fn a_share_from_an_identity_that_cannot_be_paid_is_rejected_and_its_block_relayed() {
    let node = FakeNode::start();
    let pool = started("unpayable-username", &node);
    // The identity is the username up to the first `.`, so "alice.rig1" resolves "alice".
    support::lock(&node.state).invalid_addresses.insert("alice".to_string());
    let mut gateway = ready(&pool);

    let (mut w, _) = work_with_transactions();
    w.job.merkle_branches.clear();
    w.job.txn_count = 0;
    let (from, _) = *solved();
    let (ntime, nonce) = find_nonce_with_retries(&w, from);
    let mut share = w.submit(USERNAME, ntime, nonce, TARGET_BYTE);
    share.is_block = true;

    assert_eq!(
        submit(&mut gateway, &share).verdict,
        ShareVerdict::Rejected(RejectReason::BadUsername)
    );
    assert!(
        node.wait_for_submission(Duration::from_secs(10)).is_some(),
        "the block is relayed even though its submitter cannot be paid"
    );
    assert!(pool.ledger_lines().is_empty(), "the share is not credited to an unpayable identity");
    pool.expect_line("rejecting shares from \"alice\"");
}

#[test]
#[ignore = "searches ~2^32 hashes; run with --release -- --ignored"]
fn a_block_with_transactions_is_asked_for_and_then_relayed() {
    let node = FakeNode::start();
    let pool = started("relay-full", &node);
    let mut gateway = ready(&pool);

    let (w, txns) = work_with_transactions();
    let share = solved_share(&w, true);
    gateway.send_mining(&share.encode());

    // The pool responds to the share, then requests the transactions the job listed.
    let (payload, _) = gateway.recv_until(server_subcmd::SHARE_RESPONSE);
    assert_eq!(
        ShareResponse::decode(&payload).expect("share response").verdict,
        ShareVerdict::Accepted
    );
    let (request, _) = gateway.recv_until(server_subcmd::VALIDATION);
    assert_eq!(
        request,
        validation::request_block_txns(share.job_id),
        "the pool requests the block's transactions"
    );

    let bundle = TxnBundle {
        selector: validation::response::BLOCK_TXNS,
        job_index: share.job_id,
        status: Status::Ok,
        txns: txns.clone(),
    };
    gateway.send_mining(&bundle.encode());

    let block = node.wait_for_submission(Duration::from_secs(10)).expect("the block was relayed");
    let raw = hex::decode(block).expect("block hex");
    let (ntime, nonce) = *solved();
    assert_eq!(&raw[..HEADER], &w.header(ntime, nonce, TARGET_BYTE).serialize());
    assert_eq!(raw[HEADER], 3, "coinbase and two transactions");

    let coinbase = w.full_coinbase(TARGET_BYTE);
    let mut at = HEADER + 1 + coinbase.len();
    assert_eq!(&raw[HEADER + 1..at], &coinbase[..]);
    for tx in &txns {
        assert_eq!(&raw[at..at + tx.len()], &tx[..], "each transaction is carried verbatim");
        at += tx.len();
    }
    assert_eq!(at, raw.len(), "and nothing else is");
}

#[test]
#[ignore = "searches ~2^32 hashes; run with --release -- --ignored"]
fn transactions_whose_merkle_root_is_not_the_committed_one_are_not_relayed() {
    let node = FakeNode::start();
    let pool = started("relay-mismatch", &node);
    let mut gateway = ready(&pool);

    let (w, _) = work_with_transactions();
    let share = solved_share(&w, true);
    gateway.send_mining(&share.encode());
    let (payload, _) = gateway.recv_until(server_subcmd::SHARE_RESPONSE);
    assert_eq!(
        ShareResponse::decode(&payload).expect("share response").verdict,
        ShareVerdict::Accepted
    );
    let (_request, _) = gateway.recv_until(server_subcmd::VALIDATION);

    // Respond with transactions that are not the ones the header commits to.
    let bundle = TxnBundle {
        selector: validation::response::BLOCK_TXNS,
        job_index: share.job_id,
        status: Status::Ok,
        txns: vec![simple_tx(0xc3), simple_tx(0xd4)],
    };
    gateway.send_mining(&bundle.encode());

    assert!(pool.wait_for_line("not relaying job", Duration::from_secs(10)).is_some());
    assert!(
        node.submitted().is_empty(),
        "a block whose transactions hash to a merkle root other than the committed one is not \
         submitted"
    );
    assert!(pool.logged("but the header commits to"));
}

#[test]
#[ignore = "searches ~2^32 hashes; run with --release -- --ignored"]
fn a_share_that_only_claims_to_be_a_block_is_still_only_a_share() {
    let node = FakeNode::start();
    // Whether a share is a block is checked against the node's next-block target, not the job's own
    // nbits, so it is the node's template that must be hard for the share to miss it. Set it
    // before the pool starts and reads the template. A diff-1 share cannot meet this target.
    node.set_next_bits("1b0404cb");
    let pool = started("false-block", &node);
    let mut gateway = ready(&pool);

    let (mut w, _) = work_with_transactions();
    // The job declares the same target: a job claiming an easier one than the node's is
    // rejected, so the job's bits must not be easier than the node's for the share to be
    // accepted at all.
    w.job.nbits = [0xcb, 0x04, 0x04, 0x1b];
    let (from, _) = *solved();
    let (ntime, nonce) = find_nonce_with_retries(&w, from);
    let mut share = w.submit(USERNAME, ntime, nonce, TARGET_BYTE);
    share.is_block = true;

    assert_eq!(submit(&mut gateway, &share).verdict, ShareVerdict::Accepted);
    pool.expect_line("gateway flagged a block");
    assert!(node.submitted().is_empty(), "and relays nothing");
    assert_eq!(pool.ledger_lines().len(), 1, "the share is still credited");
}

/// The pool builds the header from the job and the miner's nonce space, so rolling a field
/// the miner sets, or the time-offset selector, changes the hash it arrives at.
#[test]
#[ignore = "searches ~2^32 hashes; run with --release -- --ignored"]
fn a_share_is_hashed_from_every_field_the_miner_sets() {
    let node = FakeNode::start();
    let pool = started("hashed-fields", &node);
    let mut gateway = ready(&pool);

    let (w, _) = work_with_transactions();
    let share = solved_share(&w, false);
    let response = submit(&mut gateway, &share);
    assert_eq!(response.verdict, ShareVerdict::Accepted, "{response:?}");

    let (ntime, nonce) = *solved();
    let header = w.header(ntime, nonce, TARGET_BYTE);
    let ledger = pool.ledger_lines();
    assert_eq!(ledger.len(), 1, "{ledger:?}");
    assert!(
        ledger[0].ends_with(&hex::encode(header.hash_components().result)),
        "the ledger records the BLAKE2b proof of work: {}",
        ledger[0]
    );

    let mut wrong_field = share.clone();
    wrong_field.job_id = 1;
    wrong_field.blake2b.sia_nonce[4] = wrong_field.blake2b.sia_nonce[4].wrapping_add(1); // m_nonce2
    assert_eq!(
        submit(&mut gateway, &wrong_field).verdict,
        ShareVerdict::Rejected(RejectReason::HighHash),
        "changing a hashed field changes the hash"
    );

    // The time-offset selector is the one thing outside the nonce space that the share
    // still supplies, and it is carried in the message's reserved bytes rather than the
    // section. Setting it adds the offset to the block time, so the header the pool builds differs.
    let mut offset = share.clone();
    offset.job_id = 2;
    offset.use_time_offset = true;
    assert_eq!(
        submit(&mut gateway, &offset).verdict,
        ShareVerdict::Rejected(RejectReason::HighHash),
        "the time-offset selector is a hashed input"
    );
}
