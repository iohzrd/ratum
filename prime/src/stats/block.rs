//! The `/block.json` endpoint: one block read from the node, its coinbase decoded, with the
//! pool's record of it.

use super::{Cached, error_reply, found_block_json};
use crate::bounded::BoundedMap;
use crate::ledger::blocks::FoundBlock;
use crate::server::Server;
use log::warn;
use ratum::bitcoin::{HASH_SIZE, display_hex_bytes};
use ratum::http::{self, Reply};
use ratum::{lock, rpc};
use serde_json::{Value, json};
use std::hash::Hash;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A block hash in display order, as `FoundBlock::block_hash` holds it.
type BlockHash = [u8; HASH_SIZE];

/// How long an entry answers requests for its key: `confirmations` and `next_hash` change as
/// blocks arrive, a height's hash on a reorg, and a block the node does not hold may arrive.
const LIFETIME: Duration = Duration::from_secs(60);
/// The entries held per key space.
const CAPACITY: usize = 128;

/// One `Cached` slot per key, the least recently requested dropped past the capacity. A
/// request takes its key's slot under the map lock and computes under the slot's, so only
/// requests for one key wait together.
struct Slots<K, T>(Mutex<BoundedMap<K, Arc<Cached<T>>>>);

impl<K: Clone + Eq + Hash, T> Slots<K, T> {
    fn new(capacity: usize) -> Self {
        Self(Mutex::new(BoundedMap::new(capacity)))
    }

    fn slot(&self, key: K) -> Arc<Cached<T>> {
        let mut held = lock(&self.0);
        if let Some(slot) = held.get_renewed(&key) {
            return Arc::clone(slot);
        }
        let slot = Arc::default();
        held.insert(key, Arc::clone(&slot));
        slot
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        lock(&self.0).len()
    }
}

/// Per hash the node's answer, the block and its coinbase, and per height the hash, `None`
/// where the node holds no block, so a 404 is held as a 200 is. Two key spaces, so a run of
/// one kind evicts none of the other. The pool's record is read per request, not held.
pub(super) struct Cache {
    blocks: Slots<BlockHash, Option<(rpc::Block, rpc::Coinbase)>>,
    hashes: Slots<u32, Option<BlockHash>>,
}

impl Default for Cache {
    fn default() -> Self {
        Self { blocks: Slots::new(CAPACITY), hashes: Slots::new(CAPACITY) }
    }
}

/// The block a query names.
#[derive(Debug, PartialEq, Eq)]
enum Param {
    Hash(BlockHash),
    Height(u32),
}

fn param(query: &str) -> Result<Param, &'static str> {
    match (http::param(query, "hash"), http::param(query, "height")) {
        (Some(_), Some(_)) => Err("give hash or height, not both"),
        (None, None) => Err("hash or height is required"),
        (Some(hash), None) => {
            display_hex_bytes(&hash).map(Param::Hash).ok_or("hash must be 64 hex digits")
        }
        (None, Some(height)) => {
            let decimal = !height.is_empty() && height.bytes().all(|b| b.is_ascii_digit());
            match height.parse::<u32>() {
                Ok(height) if decimal => Ok(Param::Height(height)),
                _ => Err("height must be a decimal integer below 2^32"),
            }
        }
    }
}

fn bad_gateway(e: &rpc::Error) -> Reply {
    warn!("block.json: {e}");
    error_reply(502, &e.to_string())
}

pub(super) fn reply(server: &Server, cache: &Cache, query: &str) -> Reply {
    let hash = match param(query) {
        Err(reason) => return error_reply(400, reason),
        Ok(Param::Hash(hash)) => hash,
        Ok(Param::Height(height)) => {
            let slot = cache.hashes.slot(height);
            match slot.try_value(LIFETIME, || server.node.block_hash(height)) {
                Ok(Some(hash)) => hash,
                Ok(None) => return not_found("no block at the height", None),
                Err(e) => return bad_gateway(&e),
            }
        }
    };
    let read = cache.blocks.slot(hash).try_value(LIFETIME, || read_block(server, &hash));
    let found = lock(&server.records).block(&hash).cloned();
    match read {
        Ok(Some((block, coinbase))) => {
            let text = block_json(&block, &coinbase, found.as_ref()).to_string();
            http::noindex(http::body(text, "application/json"))
        }
        Ok(None) => not_found("no block under the hash", found.as_ref()),
        Err(e) => bad_gateway(&e),
    }
}

/// A 404 carrying the pool's record of the block when it has one: a block the pool found
/// that the node does not hold is off the node's chain, and the record is what says so.
fn not_found(reason: &str, found: Option<&FoundBlock>) -> Reply {
    let body = json!({ "error": reason, "pool": found.map(found_block_json) });
    http::noindex(http::json(body).with_status_code(404))
}

/// The block at `hash` and its coinbase, or none when the node holds no such block.
fn read_block(
    server: &Server,
    hash: &BlockHash,
) -> Result<Option<(rpc::Block, rpc::Coinbase)>, rpc::Error> {
    let Some(block) = server.node.block(&hex::encode(hash))? else { return Ok(None) };
    let coinbase = server.node.coinbase(&block)?;
    Ok(Some((block, coinbase)))
}

/// The reply body: the block, its coinbase, and the pool's record when it has one.
fn block_json(block: &rpc::Block, coinbase: &rpc::Coinbase, found: Option<&FoundBlock>) -> Value {
    json!({
        "hash": block.hash,
        "height": block.height,
        "time": block.time,
        "mediantime": block.mediantime,
        "confirmations": block.confirmations,
        "version": block.version,
        "bits": block.bits,
        "difficulty": block.difficulty,
        "nonce": block.nonce,
        "merkle_root": block.merkle_root,
        "previous_hash": block.previous_hash,
        "next_hash": block.next_hash,
        "size": block.size,
        "weight": block.weight,
        "tx_count": block.tx_count,
        "coinbase": {
            "txid": coinbase.txid,
            "script_sig": coinbase.script_sig,
            "value": coinbase.value(),
            "outputs": coinbase
                .outputs
                .iter()
                .map(|o| json!({ "value": o.sats, "address": o.address, "script": o.script }))
                .collect::<Vec<Value>>(),
        },
        "pool": found.map(found_block_json),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{ALICE, BOB, ledger_with, server, server_with};
    use crate::ledger::blocks::BlockRecords;
    use crate::stats::Stats;
    use ratum::fixtures::{FakeNode, HASH, NEXT, PREVIOUS, TXID, node_block, node_coinbase};
    use ratum::http::{Method, Request};

    fn stats(server: Server) -> Stats {
        Stats::new(Arc::new(server), Arc::default())
    }

    /// A pool with an empty window on the `FakeNode` at `url`.
    fn stats_on(node: &FakeNode) -> Stats {
        stats(server(ledger_with(&[], 0), BlockRecords::default(), &node.url()))
    }

    fn request(url: &str) -> Request {
        Request {
            method: Method::Get,
            url: url.into(),
            headers: Vec::new(),
            body: Vec::new(),
            peer: "127.0.0.1:1".parse().unwrap(),
        }
    }

    fn get(stats: &Stats, url: &str) -> Reply {
        stats.handle(&request(url))
    }

    fn body_json(reply: &Reply) -> Value {
        serde_json::from_slice(reply.body()).unwrap()
    }

    #[test]
    fn slots_hold_one_per_key_and_drop_the_least_recently_requested_past_the_capacity() {
        let slots: Slots<u32, ()> = Slots::new(3);
        let zero = slots.slot(0);
        assert!(Arc::ptr_eq(&zero, &slots.slot(0)), "one slot per key");
        let one = slots.slot(1);
        assert!(!Arc::ptr_eq(&zero, &one));
        slots.slot(2);
        assert_eq!(slots.len(), 3);
        slots.slot(0);
        slots.slot(3);
        assert_eq!(slots.len(), 3, "one was dropped for 3");
        assert!(Arc::ptr_eq(&zero, &slots.slot(0)), "0 was requested again, so it is held");
        assert!(!Arc::ptr_eq(&one, &slots.slot(1)), "1 was the least recently requested");
    }

    #[test]
    fn a_block_request_is_validated_before_the_node_is_read() {
        let s = stats(server_with(&[]));
        let bad = [
            ("/block.json", "hash or height is required"),
            ("/block.json?hash=00&height=1", "give hash or height, not both"),
            ("/block.json?hash=", "hash must be 64 hex digits"),
            (&format!("/block.json?hash={}", "0".repeat(63)), "hash must be 64 hex digits"),
            (&format!("/block.json?hash={}", "g".repeat(64)), "hash must be 64 hex digits"),
            ("/block.json?height=", "height must be a decimal integer below 2^32"),
            ("/block.json?height=-1", "height must be a decimal integer below 2^32"),
            ("/block.json?height=+1", "height must be a decimal integer below 2^32"),
            ("/block.json?height=1.5", "height must be a decimal integer below 2^32"),
            ("/block.json?height=4294967296", "height must be a decimal integer below 2^32"),
        ];
        for (url, reason) in bad {
            let reply = get(&s, url);
            assert_eq!(reply.status(), 400, "{url}");
            assert_eq!(reply.header("Content-Type"), Some("application/json"));
            assert_eq!(reply.header("X-Robots-Tag"), Some("noindex"));
            assert_eq!(body_json(&reply), json!({ "error": reason }), "{url}");
        }
        assert_eq!(
            param(&format!("hash={}", "AB".repeat(32))),
            Ok(Param::Hash([0xab; 32])),
            "hex of either case"
        );
        assert_eq!(param("height=0"), Ok(Param::Height(0)));
        assert_eq!(param("height=4294967295"), Ok(Param::Height(u32::MAX)));
        assert_eq!(s.blocks.blocks.len() + s.blocks.hashes.len(), 0, "nothing reached the node");

        let mut post = request(&format!("/block.json?hash={}", "0".repeat(64)));
        post.method = Method::Post;
        let refused = s.handle(&post);
        assert_eq!(refused.status(), 405);
        assert_eq!(body_json(&refused), json!({ "error": "method not allowed" }));
        let unknown = get(&s, "/block");
        assert_eq!(unknown.status(), 404);
        assert_eq!(unknown.header("Content-Type"), Some("application/json"));
        assert_eq!(body_json(&unknown), json!({ "error": "not found" }));
    }

    /// `node_block` decoded.
    fn block() -> rpc::Block {
        rpc::Block::decode(&node_block()).unwrap()
    }

    /// `node_coinbase([ALICE, BOB])` decoded.
    fn coinbase() -> rpc::Coinbase {
        rpc::Coinbase::decode(&node_coinbase([ALICE, BOB])).unwrap()
    }

    fn pool_block(tag: &str) -> FoundBlock {
        FoundBlock {
            found_at: 1_789_848_660,
            height: 973_054,
            block_hash: display_hex_bytes(HASH).unwrap(),
            paid_to_split: 300_000_000,
            paid_to_pool: 12_500_000,
            finder: ALICE.into(),
            tag_secondary: tag.into(),
            network_difficulty: 1234.5,
            cumulative_work: 1,
        }
    }

    #[test]
    fn a_block_is_shaped_from_the_node_answers_and_the_pool_record() {
        assert_eq!(
            block_json(&block(), &coinbase(), Some(&pool_block("public"))),
            json!({
                "hash": HASH,
                "height": 973_054,
                "time": 1_789_848_656,
                "mediantime": 1_789_848_000,
                "confirmations": 12,
                "version": 536_870_912,
                "bits": "1702c4e4",
                "difficulty": 1234.5,
                "nonce": 123_456_789u64,
                "merkle_root": "e5".repeat(32),
                "previous_hash": PREVIOUS,
                "next_hash": NEXT,
                "size": 72_907,
                "weight": 190_150,
                "tx_count": 233,
                "coinbase": {
                    "txid": TXID,
                    "script_sig": "03fed80e",
                    "value": 312_500_000u64,
                    "outputs": [
                        { "value": 300_000_000u64, "address": ALICE, "script": "0014aa" },
                        { "value": 12_500_000u64, "address": BOB, "script": "0014bb" },
                        { "value": 0, "address": null, "script": "6a24aa21a9ed" },
                    ],
                },
                "pool": {
                    "height": 973_054,
                    "block_hash": HASH,
                    "found_at": 1_789_848_660,
                    "paid_to_split": 300_000_000u64,
                    "paid_to_pool": 12_500_000u64,
                    "finder": ALICE,
                    "tag": "public",
                },
            })
        );
        let shaped = block_json(&block(), &coinbase(), Some(&pool_block("")));
        assert_eq!(shaped["pool"]["tag"], json!(""), "an empty tag, as /stats.json prints it");

        let not_ours = block_json(&block(), &coinbase(), None);
        assert_eq!(not_ours["pool"], Value::Null);

        let ends = rpc::Block { previous_hash: None, next_hash: None, ..block() };
        let shaped = block_json(&ends, &coinbase(), None);
        assert_eq!(shaped["previous_hash"], Value::Null);
        assert_eq!(shaped["next_hash"], Value::Null);
    }

    /// A node holding `node_block` alone, answering the three calls as the node does.
    fn fake_node() -> FakeNode {
        FakeNode::start(|method, params| match (method, params) {
            ("getblockhash", p) if p[0] == json!(973_054) => Ok(json!(HASH)),
            ("getblockhash", _) => Err((-8, "Block height out of range")),
            ("getblock", p) if p[0] == json!(HASH) => {
                assert_eq!(p[1], json!(1), "verbosity 1: txids alone");
                Ok(node_block())
            }
            ("getblock", _) => Err((-5, "Block not found")),
            ("getrawtransaction", p) => {
                assert_eq!(p[0], json!(TXID));
                assert_eq!(p[1], json!(true));
                assert_eq!(p[2], json!(HASH), "the block hash, so no txindex is needed");
                Ok(node_coinbase([ALICE, BOB]))
            }
            _ => Err((-32601, "Method not found")),
        })
    }

    #[test]
    fn a_block_is_read_from_the_node_once_per_lifetime_by_hash_or_height() {
        let node = fake_node();
        let s = stats_on(&node);
        lock(&s.server.records).record_block(pool_block("public")).unwrap();

        let reply = get(&s, &format!("/block.json?hash={}", HASH.to_uppercase()));
        assert_eq!(reply.status(), 200, "{}", String::from_utf8_lossy(reply.body()));
        assert_eq!(reply.header("Content-Type"), Some("application/json"));
        assert_eq!(reply.header("X-Robots-Tag"), Some("noindex"));
        let first = body_json(&reply);
        assert_eq!(first, block_json(&block(), &coinbase(), Some(&pool_block("public"))));
        assert_eq!(node.calls(), ["getblock", "getrawtransaction"]);

        let again = get(&s, &format!("/block.json?hash={HASH}"));
        assert_eq!(body_json(&again), first);
        assert_eq!(node.calls().len(), 2, "answered from the cache");

        let by_height = get(&s, "/block.json?height=973054");
        assert_eq!(body_json(&by_height), first);
        assert_eq!(node.calls().len(), 3, "the height resolved, the block from the cache");
        assert_eq!(node.calls()[2], "getblockhash");
        assert_eq!(body_json(&get(&s, "/block.json?height=973054")), first);
        assert_eq!(node.calls().len(), 3, "the height's hash is held too");

        let missing = get(&s, &format!("/block.json?hash={}", "0".repeat(64)));
        assert_eq!(missing.status(), 404);
        assert_eq!(missing.header("Content-Type"), Some("application/json"));
        assert_eq!(missing.header("X-Robots-Tag"), Some("noindex"));
        assert_eq!(
            body_json(&missing),
            json!({ "error": "no block under the hash", "pool": null })
        );
        let past_tip = get(&s, "/block.json?height=973055");
        assert_eq!(past_tip.status(), 404);
        assert_eq!(
            body_json(&past_tip),
            json!({ "error": "no block at the height", "pool": null })
        );
        assert_eq!(node.calls().len(), 5);
        assert_eq!(get(&s, &format!("/block.json?hash={}", "0".repeat(64))).status(), 404);
        assert_eq!(get(&s, "/block.json?height=973055").status(), 404);
        assert_eq!(node.calls().len(), 5, "a 404 is held as a 200 is");

        lock(&s.server.records).void_block(&display_hex_bytes(HASH).unwrap()).unwrap();
        let voided = body_json(&get(&s, &format!("/block.json?hash={HASH}")));
        assert_eq!(voided["pool"], Value::Null, "the pool record is read per request");
        assert_eq!(voided["coinbase"], first["coinbase"]);
        assert_eq!(node.calls().len(), 5, "the node's answer is still held");
    }

    #[test]
    fn a_pooled_block_the_node_does_not_hold_is_a_404_carrying_the_pool_record() {
        let node = FakeNode::start(|_, _| Err((-5, "Block not found")));
        let s = stats_on(&node);
        lock(&s.server.records).record_block(pool_block("public")).unwrap();
        let reply = get(&s, &format!("/block.json?hash={HASH}"));
        assert_eq!(reply.status(), 404);
        assert_eq!(reply.header("X-Robots-Tag"), Some("noindex"));
        let body = body_json(&reply);
        assert_eq!(body["error"], json!("no block under the hash"));
        assert_eq!(
            body["pool"],
            block_json(&block(), &coinbase(), Some(&pool_block("public")))["pool"]
        );
        assert_eq!(node.calls(), ["getblock"]);
    }

    #[test]
    fn a_node_that_fails_is_answered_as_a_bad_gateway_and_read_again() {
        let unreachable = stats(server_with(&[]));
        let reply = get(&unreachable, "/block.json?height=1");
        assert_eq!(reply.status(), 502);
        let message = body_json(&reply)["error"].as_str().unwrap().to_string();
        assert!(message.starts_with("rpc transport:"), "{message}");

        let node = FakeNode::start(|_, _| Err((-1, "Block database corrupt")));
        let s = stats_on(&node);
        let reply = get(&s, "/block.json?height=1");
        assert_eq!(reply.status(), 502);
        assert_eq!(body_json(&reply), json!({ "error": "rpc error -1: Block database corrupt" }));
        assert_eq!(get(&s, "/block.json?height=1").status(), 502);
        assert_eq!(node.calls().len(), 2, "a 502 is not held");

        let node = FakeNode::start(|method, params| match method {
            "getblockhash" if params[0] == json!(1) => Ok(json!(7)),
            "getblockhash" => Ok(json!("zz")),
            "getblock" => Ok(json!({})),
            _ => Err((-32601, "Method not found")),
        });
        let s = stats_on(&node);
        assert_eq!(
            body_json(&get(&s, "/block.json?height=1")),
            json!({ "error": "malformed rpc response: 7 is not a hash" })
        );
        assert_eq!(
            body_json(&get(&s, "/block.json?height=2")),
            json!({ "error": "malformed rpc response: \"zz\" is not a hash" })
        );
        let reply = get(&s, &format!("/block.json?hash={HASH}"));
        assert_eq!(reply.status(), 502);
        assert_eq!(body_json(&reply), json!({ "error": "malformed rpc response: no tx" }));

        let node = FakeNode::start(|method, _| match method {
            "getblock" => Ok(node_block()),
            _ => Err((-5, "No such transaction found in the provided block")),
        });
        let reply = get(&stats_on(&node), &format!("/block.json?hash={HASH}"));
        assert_eq!(reply.status(), 502, "a missing coinbase is not a missing block");
    }
}
