//! The pool's shared state: what every connection reads, and the thread that reads the
//! node's tip and block template for all of them.

use log::{error, info, warn};
use ratum::bitcoin::output_script_size_is_valid;
use ratum::datum::handshake::KeyPairs;
use ratum::datum::messages::{self, CoinbaseOutput};
use ratum::datum::verify::{PoolPolicy, ReplayGuard};
use ratum::ledger::Ledger;
use ratum::{lock, rpc};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) type SharedTip = Arc<Mutex<Option<rpc::Tip>>>;
pub(crate) type SharedCoinbaseValue = Arc<Mutex<Option<u64>>>;
/// The compact target of the block the node would build on its tip, `None` until a template
/// is read and again whenever one cannot be. A connection refuses a job claiming an easier
/// network target than this, so an ordinary share cannot be presented as a block.
pub(crate) type SharedNextBits = Arc<Mutex<Option<u32>>>;

pub(crate) fn watch_node(
    node: rpc::Client,
    tip: SharedTip,
    coinbase_value: SharedCoinbaseValue,
    next_bits: SharedNextBits,
    interval: Duration,
) {
    let mut last: Option<[u8; 32]> = None;
    // Whether the template for the current tip has been read. A template read can fail
    // transiently (the node briefly out of sync right after a block), and until it succeeds
    // the pool has no network target, so the job-target check and the coinbaser value
    // check are disabled. Retry it every iteration rather than only on the next tip change.
    let mut have_template = false;
    let mut wait_for_blocks = true;
    loop {
        let height = match node.tip() {
            Ok(t) => {
                if last != Some(t.hash) {
                    let mut display = t.hash;
                    display.reverse();
                    info!(
                        "node tip: height {} difficulty {} {}",
                        t.height,
                        t.difficulty,
                        hex::encode(display)
                    );
                    last = Some(t.hash);
                    have_template = false;
                }
                if !have_template {
                    match node.next_block() {
                        Ok(n) => {
                            info!(
                                "node template: the next coinbase may pay {} sats at bits {:#010x}",
                                n.coinbase_value, n.bits
                            );
                            *lock(&coinbase_value) = Some(n.coinbase_value);
                            *lock(&next_bits) = Some(n.bits);
                            have_template = true;
                        }
                        Err(e) => {
                            warn!("could not read a template: {e}");
                            *lock(&coinbase_value) = None;
                            *lock(&next_bits) = None;
                        }
                    }
                }
                *lock(&tip) = Some(t);
                Some(t.height)
            }
            Err(e) => {
                if e.is_unauthorized() {
                    error!(
                        "the node refused the pool's RPC credential ({e}). A cookie is \
                         generated each time the node starts; with --rpc-cookie the file is \
                         re-read on the next request, with --rpc-user/--rpc-pass the \
                         credential must match the node's configuration. Until a request \
                         is accepted no block this pool verifies can be submitted."
                    );
                } else {
                    warn!("could not read the node tip: {e}");
                }
                None
            }
        };

        match height.filter(|_| wait_for_blocks) {
            Some(h) => match node.wait_for_block_height(h + 1, interval) {
                Ok(_) => {}
                Err(e) if e.is_method_not_found() => {
                    warn!(
                        "this node does not serve waitforblockheight; \
                         polling every {:.3}s instead",
                        interval.as_secs_f64()
                    );
                    wait_for_blocks = false;
                    std::thread::sleep(interval);
                }
                Err(e) => {
                    warn!("could not wait for the next block: {e}");
                    std::thread::sleep(interval);
                }
            },
            None => std::thread::sleep(interval),
        }
    }
}

pub(crate) struct Server {
    pub(crate) pool_keys: KeyPairs,
    pub(crate) motd: String,
    pub(crate) node: rpc::Client,
    pub(crate) tip: SharedTip,
    pub(crate) coinbase_value: SharedCoinbaseValue,
    pub(crate) next_bits: SharedNextBits,
    pub(crate) replay: Arc<Mutex<ReplayGuard>>,
    pub(crate) ledger: Mutex<Ledger>,
    pub(crate) resolver: Mutex<Resolver>,
    pub(crate) payout: PayoutPolicy,
    /// What every connection's verifier checks shares against. Connection-invariant, so it
    /// is built once at startup and cloned per connection.
    pub(crate) policy: PoolPolicy,
    /// The encoded 0x99 config every connection is sent, built once from the same policy.
    pub(crate) config_payload: Vec<u8>,
    /// The count of open connections, bounded by `max_connections`.
    pub(crate) open_connections: AtomicUsize,
    pub(crate) max_connections: usize,
}

/// Decrements `open_connections` when the connection's thread ends.
pub(crate) struct OpenConnectionGuard(pub(crate) Arc<Server>);

impl Drop for OpenConnectionGuard {
    fn drop(&mut self) {
        self.0.open_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

/// There is no pool fee. `Ledger::split` divides the coinbase value to the satoshi, so the
/// pool's script is paid only on failure: an address that does not resolve, a script too
/// long to pay, an empty window, or a split `on_coinbaser_request` could not encode. Each
/// is logged.
///
/// A declared fee would be a `bps` field here, deducted before the split as a dictated output.
#[derive(Clone, Copy)]
pub(crate) struct PayoutPolicy {
    pub(crate) min_payout: u64,
    pub(crate) window_multiple: f64,
    pub(crate) window_floor: u128,
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

pub(crate) struct Resolver {
    scripts: HashMap<String, Option<Vec<u8>>>,
    order: std::collections::VecDeque<String>,
}

const MAX_CACHED_ADDRESSES: usize = 1 << 16;

impl Resolver {
    pub(crate) fn new() -> Self {
        Resolver { scripts: HashMap::new(), order: std::collections::VecDeque::new() }
    }

    fn insert(&mut self, address: &str, script: Option<Vec<u8>>) {
        if self.scripts.insert(address.to_string(), script).is_none() {
            self.order.push_back(address.to_string());
        }
        while self.order.len() > MAX_CACHED_ADDRESSES {
            if let Some(old) = self.order.pop_front() {
                self.scripts.remove(&old);
            }
        }
    }

    fn script_for(cache: &Mutex<Self>, node: &rpc::Client, address: &str) -> Option<Vec<u8>> {
        if let Some(known) = lock(cache).scripts.get(address) {
            return known.clone();
        }
        let resolved = match resolve_address(node, address) {
            Ok(Resolved::Script(script)) => Some(script),
            Ok(Resolved::Invalid) => {
                warn!("payout address {address:?} is not valid; it will not be paid");
                None
            }
            Ok(Resolved::NoScript) => None,
            Err(e) => {
                warn!("could not resolve payout address {address:?}: {e}");
                return None;
            }
        };
        lock(cache).insert(address, resolved.clone());
        resolved
    }
}

/// What the node's `validateaddress` returns for `address`.
pub(crate) enum Resolved {
    Script(Vec<u8>),
    /// The node reports the address as not valid.
    Invalid,
    /// Valid, but the node returned no script for it.
    NoScript,
}

pub(crate) fn resolve_address(node: &rpc::Client, address: &str) -> Result<Resolved, rpc::Error> {
    let v = node.call("validateaddress", serde_json::json!([address]))?;
    if v["isvalid"] != serde_json::Value::Bool(true) {
        return Ok(Resolved::Invalid);
    }
    Ok(match v["scriptPubKey"].as_str().and_then(|h| hex::decode(h).ok()) {
        Some(script) => Resolved::Script(script),
        None => Resolved::NoScript,
    })
}

pub(crate) fn coinbaser_outputs(server: &Server, value: u64) -> (Vec<CoinbaseOutput>, usize, u128) {
    let node = &server.node;
    let (split, shares, work) = {
        let l = lock(&server.ledger);
        (
            l.split(value, server.payout.min_payout, messages::MAX_COINBASER_OUTPUTS),
            l.len(),
            l.total_work(),
        )
    };
    let mut outputs = Vec::with_capacity(split.len());
    for (identity, amount) in split {
        if let Some(script) = Resolver::script_for(&server.resolver, node, &identity) {
            if !output_script_size_is_valid(&script) {
                warn!(
                    "      {identity} resolves to a {}-byte script, too long for a coinbase \
                     output; paying the other outputs and leaving this identity's amount to \
                     the pool",
                    script.len()
                );
                continue;
            }
            outputs.push(CoinbaseOutput { value: amount, script });
        }
    }
    (outputs, shares, work)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratum::datum::messages::ClientConfig;

    /// `script_for` returns from its cache before calling the node, so the node client, which
    /// cannot connect, is never called.
    fn server_with(
        shares: &[(&str, u64)],
        resolved: &[(&str, Option<Vec<u8>>)],
        min_payout: u64,
    ) -> Server {
        let mut ledger = Ledger::new(u128::MAX);
        for (i, (identity, difficulty)) in shares.iter().enumerate() {
            let mut hash = [0u8; 32];
            hash[0] = i as u8;
            ledger.record(1_000 + i as u64, identity, *difficulty, &hash).unwrap();
        }
        let mut resolver = Resolver::new();
        for (address, script) in resolved {
            resolver.insert(address, script.clone());
        }
        let config = ClientConfig {
            payout_script: POOL.to_vec(),
            prime_id: 1,
            coinbase_tag: "RATUM".into(),
            min_difficulty: 1,
        };
        Server {
            pool_keys: KeyPairs::generate(),
            motd: String::new(),
            node: rpc::Client::new("http://127.0.0.1:1", "u", "p").unwrap(),
            tip: Arc::new(Mutex::new(None)),
            coinbase_value: Arc::new(Mutex::new(None)),
            next_bits: Arc::new(Mutex::new(None)),
            replay: Arc::new(Mutex::new(ReplayGuard::default())),
            ledger: Mutex::new(ledger),
            resolver: Mutex::new(resolver),
            payout: PayoutPolicy { min_payout, window_multiple: 8.0, window_floor: 1 },
            config_payload: config.encode().unwrap(),
            policy: PoolPolicy::from_config(&config),
            open_connections: AtomicUsize::new(0),
            max_connections: 8,
        }
    }

    const POOL: [u8; 4] = [0x00, 0x14, 0xee, 0xee];
    fn p2wpkh(fill: u8) -> Vec<u8> {
        let mut v = vec![0x00, 0x14];
        v.extend_from_slice(&[fill; 20]);
        v
    }

    #[test]
    fn a_split_names_every_miner_and_never_the_pool() {
        let server = server_with(
            &[("alice", 3), ("bob", 1)],
            &[("alice", Some(p2wpkh(0xa1))), ("bob", Some(p2wpkh(0xb2)))],
            0,
        );
        let (outputs, shares, work) = coinbaser_outputs(&server, 1_000_000);
        assert_eq!(shares, 2);
        assert_eq!(work, 4);
        assert_eq!(
            outputs.iter().map(|o| (o.value, o.script.clone())).collect::<Vec<_>>(),
            vec![(750_000, p2wpkh(0xa1)), (250_000, p2wpkh(0xb2))]
        );
        // Fully allocated, so the gateway has no remainder to pay to the pool.
        assert_eq!(outputs.iter().map(|o| o.value).sum::<u64>(), 1_000_000);
        assert!(outputs.iter().all(|o| o.script != POOL));
    }

    #[test]
    fn an_empty_window_names_nobody() {
        let server = server_with(&[], &[], 0);
        let (outputs, shares, work) = coinbaser_outputs(&server, 1_000_000);
        assert!(outputs.is_empty());
        assert_eq!((shares, work), (0, 0));
    }

    #[test]
    fn an_address_that_does_not_resolve_leaves_its_amount_to_the_pool() {
        // Dropped after the split counted its work, so its amount becomes the remainder
        // the gateway pays to the pool.
        let server = server_with(
            &[("alice", 3), ("nonsense", 1)],
            &[("alice", Some(p2wpkh(0xa1))), ("nonsense", None)],
            0,
        );
        let (outputs, _, _) = coinbaser_outputs(&server, 1_000_000);
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].script, p2wpkh(0xa1));
        assert_eq!(outputs[0].value, 750_000);
        assert_eq!(1_000_000 - outputs[0].value, 250_000);
    }

    #[test]
    fn a_script_too_long_to_pay_is_left_out_rather_than_sent() {
        // A coinbase output script may be at most 34 bytes; a longer one builds a block the
        // network rejects.
        let long = vec![0x00; 35];
        assert!(!output_script_size_is_valid(&long));
        let server = server_with(
            &[("alice", 3), ("toolong", 1)],
            &[("alice", Some(p2wpkh(0xa1))), ("toolong", Some(long))],
            0,
        );
        let (outputs, _, _) = coinbaser_outputs(&server, 1_000_000);
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].script, p2wpkh(0xa1));
    }

    #[test]
    fn the_minimum_is_applied_before_addresses_are_resolved() {
        // The small miner is removed from the split and its work leaves the denominator, so the
        // large one takes the whole value, not 999_000.
        let server = server_with(
            &[("large", 999), ("small", 1)],
            &[("large", Some(p2wpkh(0xa1))), ("small", Some(p2wpkh(0xb2)))],
            10_000,
        );
        let (outputs, shares, _) = coinbaser_outputs(&server, 1_000_000);
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].value, 1_000_000);
        // Still in the window and counted, but unpaid.
        assert_eq!(shares, 2);
    }
}
