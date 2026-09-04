//! What a version 3 gateway (one whose hello carries the DRS extension) receives from
//! `ratum-prime`: a version 3 configuration with a resume token, an anti-block-withholding
//! assignment that rotates and is revealed, bulk-framed replies acknowledged, and share
//! handling that requires the assignment slot. The release binary is driven through a TCP
//! connection, so the generation branch in the connection loop is under test.

mod support;

use ratum::bitcoin;
use ratum::datum::abw::{self, AssignmentNotice, Candidate, Reveal};
use ratum::datum::bulk;
use ratum::datum::framing;
use ratum::datum::messages::{
    ClientConfigV3, CoinbaserRequest, CoinbaserResponse, RejectReason, ShareResponse, ShareVerdict,
    server_subcmd, token_matches_prime_id,
};
use ratum::datum::validation::{self, Status, TxnBundle};
use ratum::target;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use support::work::{self, Tagging, Work};
use support::{FakeNode, Gateway, Pool, PoolArgs, TIMEOUT, TempDir, script_for_address};

const PRIME_ID: u64 = 0x0102_0304;
/// The bytes of a serialized version 2 header.
const HEADER: usize = ratum::header::HEADER_V2_SIZE;

fn started(dir: &str, node: &FakeNode) -> Pool {
    node.set_tip(&"5a".repeat(32), 840_000);
    support::lock(&node.state).coinbase_value = Some(work::COINBASE_VALUE);
    Pool::start(
        TempDir::new(dir),
        PoolArgs {
            rpc_url: Some(node.url()),
            min_payout: 1,
            prime_id: PRIME_ID as u32,
            ..Default::default()
        },
    )
}

fn pool_payout_script() -> Vec<u8> {
    script_for_address("pool")
}

fn unix_now() -> u32 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32
}

/// The next assignment notice with the active flag. On a resume the retired slot's notice
/// precedes it.
fn active_notice(gateway: &mut Gateway) -> AssignmentNotice {
    for _ in 0..4 {
        let (payload, _) = gateway.recv_until(abw::subcmd::ASSIGNMENT_NOTICE);
        let notice = AssignmentNotice::decode(&payload).expect("assignment notice decodes");
        if notice.active {
            return notice;
        }
    }
    panic!("no active assignment notice");
}

/// Read the version 3 configuration and the ABW assignment notices a session is sent, and
/// return the config and the active assignment's key hash and slot.
fn read_setup(gateway: &mut Gateway) -> (ClientConfigV3, [u8; 32], u8) {
    let (config_payload, _) = gateway.recv_until(server_subcmd::CONFIG);
    let config = ClientConfigV3::decode(&config_payload).expect("v3 config decodes");
    let notice = active_notice(gateway);
    (config, notice.key_hash, notice.slot)
}

fn v3_work(key_hash: [u8; 32], slot: u8) -> Work {
    Work::build(
        &Tagging { tag: "RATUM", prime_id: PRIME_ID as u32 },
        &pool_payout_script(),
        &[],
        work::COINBASE_VALUE,
    )
    .with_abw(key_hash, slot)
}

fn submit(gateway: &mut Gateway, s: &ratum::datum::share::PowSubmit) -> ShareResponse {
    gateway.send_mining(&s.encode());
    let (payload, _) = gateway.recv_until(server_subcmd::SHARE_RESPONSE);
    ShareResponse::decode(&payload).expect("share response decodes")
}

/// Wait until the pool has logged `needle` at least `count` times.
fn logged_count(pool: &Pool, needle: &str, count: usize) {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let n = pool.lines().iter().filter(|l| l.contains(needle)).count();
        if n >= count {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{needle:?} logged {n} times, wanted {count}:\n{}",
            pool.lines().join("\n")
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The next bulk acknowledgement (command 6).
fn recv_ack(gateway: &mut Gateway) -> bulk::Ack {
    for _ in 0..64 {
        let (header, payload) = gateway.recv();
        if header.proto_cmd == framing::cmd::BULK {
            return bulk::Ack::decode(&payload).expect("ack decodes");
        }
    }
    panic!("no bulk acknowledgement");
}

/// Send `payload` as the C gateway sends a bulk reply: one fragment at a time, each
/// acknowledged at the offset the sender advanced to.
fn send_bulk(gateway: &mut Gateway, id: u32, payload: &[u8]) {
    for f in bulk::split(id, payload) {
        gateway.send(framing::cmd::BULK, &f.encode());
        assert_eq!(
            recv_ack(gateway),
            bulk::Ack { id, next_offset: f.offset + f.data.len() as u32 }
        );
    }
}

#[test]
fn a_v3_hello_receives_a_v3_config_a_resume_token_and_an_abw_assignment() {
    let node = FakeNode::start();
    let pool = started("v3-setup", &node);
    let mut gateway = pool.connect_v3(None);

    let (config, key_hash, slot) = read_setup(&mut gateway);
    assert_eq!(config.prime_id, PRIME_ID, "the v3 config carries the 64-bit prime id");
    assert!(config.bulk_framing, "bulk framing is advertised");
    assert!(!config.abw_disabled, "the pool runs anti-block-withholding");
    assert!(
        token_matches_prime_id(&config.resume_token, PRIME_ID),
        "the resume token's prefix is the prime id"
    );
    assert_eq!(slot, 0, "the first assignment is slot 0");
    assert_ne!(key_hash, [0u8; 32], "the assignment commits to a real key");
}

#[test]
fn presenting_the_configured_token_resumes_the_saved_session() {
    let node = FakeNode::start();
    let pool = started("v3-resume", &node);

    let mut first = pool.connect_v3(None);
    let keys = first.long_term_keys();
    let (config, key_hash, slot) = read_setup(&mut first);
    let token = config.resume_token;
    // The session's first split takes coinbaser id 1.
    let request = CoinbaserRequest { value: work::COINBASE_VALUE, prev_hash: work::PREV_HASH };
    first.send_mining(&request.encode());
    let (response, _) = first.recv_until(server_subcmd::COINBASER);
    assert_eq!(CoinbaserResponse::decode(&response).unwrap().coinbaser_id, 1);
    drop(first);
    pool.expect_line("session saved for resume");

    // The token under the same signing key continues the session: the same token is
    // configured and the same assignment is announced again, and the next split continues
    // the session's ids (a held job still names id 1).
    let mut second = pool.connect_v3_as(Some(token), keys.clone());
    let (config2, key_hash2, slot2) = read_setup(&mut second);
    assert_eq!(config2.resume_token, token);
    assert_eq!((key_hash2, slot2), (key_hash, slot));
    pool.expect_line("resume accepted");
    second.send_mining(&request.encode());
    let (response, _) = second.recv_until(server_subcmd::COINBASER);
    assert_eq!(CoinbaserResponse::decode(&response).unwrap().coinbaser_id, 2);
    drop(second);
    logged_count(&pool, "session saved for resume", 2);

    // Another token under the same key is declined: a new token and a new assignment.
    let mut third = pool.connect_v3_as(Some([9u8; 40]), keys);
    let (config3, key_hash3, _) = read_setup(&mut third);
    assert_ne!(config3.resume_token, token);
    assert!(token_matches_prime_id(&config3.resume_token, PRIME_ID));
    assert_ne!(key_hash3, key_hash);
    pool.expect_line("resume declined");
    drop(third);
    logged_count(&pool, "session saved for resume", 3);

    // The token under other keys is declined: a saved session is under its signing key.
    let mut other = pool.connect_v3(Some(config3.resume_token));
    let (config4, _, _) = read_setup(&mut other);
    assert_ne!(config4.resume_token, config3.resume_token);
    logged_count(&pool, "resume declined", 2);
}

#[test]
fn a_share_naming_an_unseeded_slot_is_refused() {
    let node = FakeNode::start();
    let pool = started("v3-badslot", &node);
    let mut gateway = pool.connect_v3(None);
    let (_, key_hash, _) = read_setup(&mut gateway);

    // Slot 5 was never seeded (only slot 0 is active), so the share is refused before its
    // proof of work is hashed.
    let w = v3_work(key_hash, 5);
    let share = w.submit("alice.rig1", unix_now(), 0, 0);
    let response = submit(&mut gateway, &share);
    assert_eq!(response.verdict, ShareVerdict::Rejected(RejectReason::BadAbwSlot), "{response:?}");
    assert!(response.abw_ref.is_none(), "no work rebuilds without a seeded slot");
}

#[test]
fn a_share_that_does_not_decode_is_answered_with_its_prefix_fields() {
    let node = FakeNode::start();
    let pool = started("v3-undecodable", &node);
    let mut gateway = pool.connect_v3(None);
    let (_, key_hash, slot) = read_setup(&mut gateway);

    // Cut inside the sections: the response names the job, target byte and nonce from the
    // prefix, by which the gateway retires its replay entry.
    let share = v3_work(key_hash, slot).submit("alice.rig1", unix_now(), 0x0102_0304, 0);
    let mut bytes = share.encode();
    bytes.truncate(60);
    gateway.send_mining(&bytes);
    let (payload, _) = gateway.recv_until(server_subcmd::SHARE_RESPONSE);
    let response = ShareResponse::decode(&payload).expect("share response decodes");
    assert_eq!(response.verdict, ShareVerdict::Rejected(RejectReason::Other));
    assert_eq!(
        (response.job_id, response.target_byte, response.nonce),
        (share.job_id, 0, 0x0102_0304)
    );
    assert!(response.abw_ref.is_none());
}

#[test]
fn a_share_on_the_active_slot_is_hashed_and_a_below_target_one_is_high_hash() {
    let node = FakeNode::start();
    let pool = started("v3-highhash", &node);
    let mut gateway = pool.connect_v3(None);
    let (_, key_hash, slot) = read_setup(&mut gateway);

    // A share on the seeded slot passes slot validation and is hashed; nonce 0 does not meet
    // the difficulty-1 share target, so it is HighHash, not BadAbwSlot. This tests the
    // key-hash commitment computation without a 2^32 search.
    let w = v3_work(key_hash, slot);
    let (ntime, nonce) = (unix_now(), 0);
    let share = w.submit("alice.rig1", ntime, nonce, 0);
    let response = submit(&mut gateway, &share);
    assert_eq!(
        response.verdict,
        ShareVerdict::Rejected(RejectReason::HighHash),
        "the slot is accepted and the below-target share is refused on its hash: {response:?}"
    );
    // A refused share that rebuilt still carries the exact reference, in the reversed order
    // the gateway retains its proof under, so the gateway retires exactly its replay entry.
    let abw_ref = response.abw_ref.expect("the refused share carries the exact reference");
    assert_eq!(abw_ref.slot, slot);
    assert_eq!(abw_ref.raw_pow_hash, abw::raw_hash_le(&w.raw_hash(ntime, nonce, 0)));
}

#[test]
fn a_tip_change_rotates_the_assignment_and_the_retired_slot_is_revealed_after_the_delay() {
    let node = FakeNode::start();
    node.set_tip(&"5a".repeat(32), 840_000);
    support::lock(&node.state).coinbase_value = Some(work::COINBASE_VALUE);
    // A 2 s reveal delay, so the reveal is observed; a tip rotates the assignment only once
    // the active slot is a quarter of that old.
    let pool = Pool::start(
        TempDir::new("v3-rotate"),
        PoolArgs {
            rpc_url: Some(node.url()),
            min_payout: 1,
            prime_id: PRIME_ID as u32,
            extra: vec!["--abw-reveal-after".to_string(), "2".to_string()],
            ..Default::default()
        },
    );
    let mut gateway = pool.connect_v3(None);
    let (_, hash0, slot0) = read_setup(&mut gateway);
    assert_eq!(slot0, 0);

    // The rotation activates slot 1 and reveals nothing: slot 0 stays seeded for the shares
    // sent before the gateway received the notice.
    std::thread::sleep(Duration::from_millis(600));
    node.set_tip(&"5b".repeat(32), 840_001);
    assert_eq!(active_notice(&mut gateway).slot, 1);
    pool.expect_line("rotated the ABW assignment (new tip)");
    assert!(gateway.received_no(abw::subcmd::REVEAL, Duration::from_millis(500)));

    // A share on the retired slot is still hashed (and refused on its hash only).
    let mut w = v3_work(hash0, 0);
    w.job.prev_hash = [0x5b; 32];
    let response = submit(&mut gateway, &w.submit("alice.rig1", unix_now(), 0, 0));
    assert_eq!(response.verdict, ShareVerdict::Rejected(RejectReason::HighHash), "{response:?}");

    // Retired for the delay, slot 0 is revealed with the key its commitment names.
    let (payload, _) = gateway.recv_until(abw::subcmd::REVEAL);
    let reveal = Reveal::decode(&payload).expect("reveal decodes");
    assert_eq!(reveal.slot, 0);
    assert!(
        abw::key_matches_hash(&reveal.xor_key, &hash0),
        "the revealed key is the committed one"
    );
    pool.expect_line("revealed the retired ABW slot 0");

    // A share on the revealed slot is refused, its key being public, and still rebuilt with
    // that key for the exact reference.
    let mut w = v3_work(hash0, 0);
    w.job.prev_hash = [0x5b; 32];
    let response = submit(&mut gateway, &w.submit("alice.rig1", unix_now(), 1, 0));
    assert_eq!(response.verdict, ShareVerdict::Rejected(RejectReason::BadAbwSlot), "{response:?}");
    assert_eq!(response.abw_ref.map(|r| r.slot), Some(0), "rebuilt with the revealed key");

    // The next tip rotates again: slot 1 is old enough by now.
    node.set_tip(&"5c".repeat(32), 840_002);
    assert_eq!(active_notice(&mut gateway).slot, 2);
}

#[test]
fn bulk_fragments_are_acknowledged_and_reassembled_and_a_stray_one_is_acknowledged_too() {
    let node = FakeNode::start();
    let pool = started("v3-bulk", &node);
    let mut gateway = pool.connect_v3(None);
    read_setup(&mut gateway);

    // A coinbaser request padded past one fragment, as the C gateway pads its replies. The
    // reassembled payload is dispatched as a single frame would be, so the pool responds with
    // a split.
    let request = CoinbaserRequest { value: work::COINBASE_VALUE, prev_hash: work::PREV_HASH };
    let mut payload = request.encode();
    payload.resize(bulk::FRAGMENT_DATA_SIZE + 100, 0x77);
    assert_eq!(bulk::split(1, &payload).len(), 2);
    send_bulk(&mut gateway, 1, &payload);
    let (response, _) = gateway.recv_until(server_subcmd::COINBASER);
    let split = CoinbaserResponse::decode(&response).expect("coinbaser response decodes");
    assert_eq!(split.value, work::COINBASE_VALUE);

    // A fragment that continues no transfer is refused, acknowledged at the offset it claims
    // (the C sender advances on nothing else), and discarded.
    let stray = bulk::Fragment { id: 2, total_size: 100, offset: 40, data: &[1u8; 10] };
    gateway.send(framing::cmd::BULK, &stray.encode());
    assert_eq!(recv_ack(&mut gateway), bulk::Ack { id: 2, next_offset: 50 });
    pool.expect_line("bulk fragment refused");

    // The next transfer starts from nothing.
    send_bulk(&mut gateway, 3, &request.encode());
    gateway.recv_until(server_subcmd::COINBASER);
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

/// Version 3 work with two other transactions in the block, and the merkle branch that
/// commits to them: for three leaves the branch is the second transaction, then the third
/// paired with itself.
fn work_with_transactions(key_hash: [u8; 32], slot: u8) -> (Work, Vec<Vec<u8>>) {
    let txns = vec![simple_tx(0xa1), simple_tx(0xb2)];
    let a = bitcoin::txid(&txns[0]).expect("txid a");
    let b = bitcoin::txid(&txns[1]).expect("txid b");
    let mut paired = [0u8; 64];
    paired[..32].copy_from_slice(&b);
    paired[32..].copy_from_slice(&b);
    let mut w = v3_work(key_hash, slot);
    w.job.merkle_branches = vec![a, bitcoin::sha256d(&paired)];
    w.job.txn_count = txns.len() as u32;
    (w, txns)
}

/// A nonce for `w` at difficulty 1, searching the ntime window from now.
fn solve(w: &Work) -> (u32, u32) {
    let target = target::target_for_pot(0);
    let now = unix_now();
    (now..now + 600)
        .find_map(|t| w.find_nonce(t, 0, &target).map(|n| (t, n)))
        .expect("a difficulty-1 hash within the ntime window")
}

#[test]
#[ignore = "searches ~2^32 hashes; run with --release -- --ignored"]
fn a_solved_v3_share_is_accepted_with_the_exact_abw_reference() {
    let node = FakeNode::start();
    // A network target no share meets, so the share is a share and not a block; the job
    // claims the same target (a job easier than the node's next block is refused).
    node.set_next_bits("1c00ffff");
    let pool = started("v3-accept", &node);
    let mut gateway = pool.connect_v3(None);
    let (_, key_hash, slot) = read_setup(&mut gateway);

    let mut w = v3_work(key_hash, slot);
    w.job.nbits = work::HARD_NBITS;
    let (ntime, nonce) = solve(&w);
    // The gateway searches the raw (unmasked) hash, the top bits of which the mask leaves
    // clear; the pool checks the same raw hash against the share target.
    let raw = w.raw_hash(ntime, nonce, 0);
    assert!(target::meets_target(&raw, &target::target_for_pot(0)));

    let share = w.submit("alice.rig1", ntime, nonce, 0);
    let response = submit(&mut gateway, &share);
    assert_eq!(response.verdict, ShareVerdict::Accepted, "{response:?}");
    let abw_ref = response.abw_ref.expect("the response carries the exact ABW reference");
    assert_eq!(abw_ref.slot, slot);
    assert_eq!(
        abw_ref.raw_pow_hash,
        abw::raw_hash_le(&raw),
        "the reference names the unmasked hash in the reversed order the gateway retains"
    );
    assert!(gateway.received_no(abw::subcmd::CANDIDATE_RECEIPT, Duration::from_millis(500)));
}

#[test]
#[ignore = "searches ~2^32 hashes; run with --release -- --ignored"]
fn a_v3_block_gets_a_receipt_and_is_relayed_after_its_bulk_framed_transactions() {
    let node = FakeNode::start();
    let pool = started("v3-relay", &node);
    let mut gateway = pool.connect_v3(None);
    let (_, key_hash, slot) = read_setup(&mut gateway);

    let (w, txns) = work_with_transactions(key_hash, slot);
    let (ntime, nonce) = solve(&w);
    let raw = w.raw_hash(ntime, nonce, 0);
    let share = w.submit("alice.rig1", ntime, nonce, 0);
    gateway.send_mining(&share.encode());

    // Under regtest's network target the share is a block by its masked hash, which only
    // the pool computes: the receipt precedes the response, then the block's transactions
    // are requested.
    let (payload, _) = gateway.recv_until(abw::subcmd::CANDIDATE_RECEIPT);
    let receipt = Candidate::decode(&payload, abw::subcmd::CANDIDATE_RECEIPT).unwrap();
    assert_eq!((receipt.slot, receipt.raw_pow_hash), (slot, abw::raw_hash_le(&raw)));
    let (payload, _) = gateway.recv_until(server_subcmd::SHARE_RESPONSE);
    assert_eq!(ShareResponse::decode(&payload).unwrap().verdict, ShareVerdict::Accepted);
    let (request, _) = gateway.recv_until(server_subcmd::VALIDATION);
    assert_eq!(request, validation::request_block_txns(share.job_id));

    // The C gateway sends every block-transactions reply through bulk framing.
    let bundle = TxnBundle {
        selector: validation::response::BLOCK_TXNS,
        job_index: share.job_id,
        status: Status::Ok,
        txns: txns.clone(),
    };
    send_bulk(&mut gateway, 1, &bundle.encode());

    let block = node.wait_for_submission(Duration::from_secs(10)).expect("the block was relayed");
    let block = hex::decode(block).expect("block hex");
    // The relayed header is the gateway's with the pool's key in the XOR key field.
    let expected = w.header(ntime, nonce, 0).serialize();
    assert_eq!(&block[..112], &expected[..112]);
    let key: [u8; 16] = block[112..128].try_into().unwrap();
    assert!(abw::key_matches_hash(&key, &key_hash), "the header carries the committed key");
    assert_eq!(&block[128..HEADER], &expected[128..HEADER]);
    assert_eq!(block[HEADER], 3, "coinbase and two transactions");
    let coinbase = w.full_coinbase(0);
    let mut at = HEADER + 1 + coinbase.len();
    assert_eq!(&block[HEADER + 1..at], &coinbase[..]);
    for tx in &txns {
        assert_eq!(&block[at..at + tx.len()], &tx[..], "each transaction is carried verbatim");
        at += tx.len();
    }
    assert_eq!(at, block.len());
}

/// With `--require-v3` the pool refuses a hello that carries no DRS extension. The refusal
/// closes the socket before any handshake response, which is why this sends a raw version 1
/// hello over a plain socket rather than through the harness `Gateway` (it would panic on
/// the missing response). A version 3 hello on the same pool is served as usual.
#[test]
fn with_require_v3_a_v1_hello_is_refused_and_a_v3_hello_is_served() {
    use ratum::datum::client::Client;
    use ratum::datum::handshake::KeyPairs;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let node = FakeNode::start();
    node.set_tip(&"5a".repeat(32), 840_000);
    support::lock(&node.state).coinbase_value = Some(work::COINBASE_VALUE);
    let pool = Pool::start(
        TempDir::new("v3-required"),
        PoolArgs {
            rpc_url: Some(node.url()),
            min_payout: 1,
            prime_id: PRIME_ID as u32,
            extra: vec!["--require-v3".to_string()],
            ..Default::default()
        },
    );
    pool.expect_line("version 3 protocol required");

    // A version 1 hello: no DRS extension. The pool closes the connection without a
    // handshake response and logs why.
    let mut stream = TcpStream::connect(pool.addr).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).expect("read timeout");
    let mut v1 = Client::with_key_pairs(KeyPairs::generate(), KeyPairs::generate(), 0x0bad_f00d);
    let hello = v1.hello(&pool.box_pk(), "v0.4.1-beta/old-gateway");
    stream.write_all(&hello).expect("send v1 hello");
    stream.flush().expect("flush");
    let mut head = [0u8; 4];
    let outcome = stream.read(&mut head);
    assert!(
        matches!(outcome, Ok(0) | Err(_)),
        "a refused v1 hello gets no handshake response, got {outcome:?}"
    );
    pool.expect_line("hello refused");
    pool.expect_line("requires version 3");

    // A version 3 hello on the same pool is served: v3 config and an assignment.
    let mut gateway = pool.connect_v3(None);
    let (config, _, slot) = read_setup(&mut gateway);
    assert_eq!(config.prime_id, PRIME_ID);
    assert_eq!(slot, 0);
}
