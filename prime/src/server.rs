//! The pool's shared state: what every connection reads, and the thread that reads the
//! node's tip and block template for all of them.

use log::{error, info, warn};
use ratum::bitcoin::output_script_size_is_valid;
use ratum::datum::handshake::KeyPairs;
use ratum::datum::messages::{self, CoinbaseOutput};
use ratum::{lock, rpc};
use ratum_prime::ledger::Ledger;
use ratum_prime::verify::{PoolPolicy, ReplayGuard};
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
    expected_chain: Option<rpc::Chain>,
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
                // The ledger is named after and stamped with the chain the pool started on;
                // a node moved to another chain under a running pool would have its shares
                // credited to that ledger, so stop instead.
                match expected_chain {
                    Some(expected) if t.chain != expected => {
                        error!(
                            "the node is on chain {} but this pool started on chain {} and \
                             its ledger holds {} shares; exiting rather than credit shares \
                             of one chain to the ledger of another",
                            t.chain.name(),
                            expected.name(),
                            expected.name()
                        );
                        std::process::exit(1);
                    }
                    _ => {}
                }
                if last != Some(t.hash) {
                    let mut display = t.hash;
                    display.reverse();
                    info!(
                        "node tip: height {} difficulty {} {} (chain {})",
                        t.height,
                        t.difficulty,
                        hex::encode(display),
                        t.chain.name()
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
    /// The port a gateway connects to (the `--listen` port), reported by the stats interface
    /// so the page can show how to reach the pool.
    pub(crate) datum_port: u16,
    /// The host, or `host:port`, gateways should use to reach the pool (`--advertise-address`).
    /// `None` falls back to the address the stats page was reached on. The stats interface only
    /// displays it.
    pub(crate) advertise: Option<String>,
}

/// Decrements `open_connections` when the connection's thread ends.
pub(crate) struct OpenConnectionGuard(pub(crate) Arc<Server>);

impl Drop for OpenConnectionGuard {
    fn drop(&mut self) {
        self.0.open_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

/// `fee_bps` is the operator fee in basis points (hundredths of a percent), 0 to 100, so at
/// most 1% (`main` refuses more). The pool receives it: `value - fee` is split among the
/// miners, and the gateway pays the fee to the pool's payout script as the coinbase remainder,
/// by the same mechanism as the pool's fallback residue (an address that does not resolve, a
/// script too long to pay, an empty window, or a split that could not be encoded). `fee_bps`
/// is 0 by default, so nothing is withheld and `Ledger::split` divides the whole coinbase
/// value to the satoshi.
#[derive(Clone, Copy)]
pub(crate) struct PayoutPolicy {
    pub(crate) min_payout: u64,
    pub(crate) window_multiple: f64,
    pub(crate) window_floor: u128,
    pub(crate) fee_bps: u16,
}

impl PayoutPolicy {
    /// The operator fee taken from a coinbase value of `value` sats: `fee_bps` hundredths of a
    /// percent, rounded down so the operator never takes more than the exact rate.
    pub(crate) fn fee_on(&self, value: u64) -> u64 {
        (u128::from(value) * u128::from(self.fee_bps) / 10_000) as u64
    }
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

pub(crate) struct Resolver {
    scripts: HashMap<String, Result<Vec<u8>, Unpayable>>,
    order: std::collections::VecDeque<String>,
}

const MAX_CACHED_ADDRESSES: usize = 1 << 16;

/// Why an identity cannot be paid a coinbase output. Determined by the node, so it does not
/// change until the identity does, and is cached with the identity.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Unpayable {
    /// `validateaddress` reports the identity is not a valid address.
    NotAnAddress,
    /// A valid address the node returned no `scriptPubKey` for.
    NoScript,
    /// Longer than a coinbase output may be (`output_script_size_is_valid`).
    ScriptTooLong(usize),
}

impl std::fmt::Display for Unpayable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unpayable::NotAnAddress => write!(f, "not a valid address"),
            Unpayable::NoScript => write!(f, "an address the node returns no script for"),
            Unpayable::ScriptTooLong(n) => {
                write!(f, "over the coinbase output limit ({n} bytes)")
            }
        }
    }
}

/// Whether an identity can be paid a coinbase output.
pub(crate) enum Payability {
    Script(Vec<u8>),
    Unpayable(Unpayable),
    /// The node could not be asked. Distinct from `Unpayable` so an RPC failure does not make
    /// the pool refuse an identity that is valid: the caller treats it as payable.
    Unknown,
}

impl Resolver {
    pub(crate) fn new() -> Self {
        Resolver { scripts: HashMap::new(), order: std::collections::VecDeque::new() }
    }

    fn insert(&mut self, address: &str, script: Result<Vec<u8>, Unpayable>) {
        if self.scripts.insert(address.to_string(), script).is_none() {
            self.order.push_back(address.to_string());
        }
        while self.order.len() > MAX_CACHED_ADDRESSES {
            if let Some(old) = self.order.pop_front() {
                self.scripts.remove(&old);
            }
        }
    }

    /// The cached answer for `address`, without asking the node. The stats interface reads
    /// through this so an unauthenticated HTTP request cannot make the pool call the node.
    pub(crate) fn cached(cache: &Mutex<Self>, address: &str) -> Option<Result<Vec<u8>, Unpayable>> {
        lock(cache).scripts.get(address).cloned()
    }

    /// Resolve `address` through `validateaddress`, from the cache when it has been resolved
    /// before. A determinate answer (a script, or a reason it cannot be paid) is cached; an
    /// RPC failure is not, so the next call asks again.
    pub(crate) fn payability(cache: &Mutex<Self>, node: &rpc::Client, address: &str) -> Payability {
        if let Some(known) = Resolver::cached(cache, address) {
            return known.into();
        }
        let resolved = match resolve_address(node, address) {
            Ok(r) => classify(r),
            Err(e) => {
                warn!("could not resolve payout address {address:?}: {e}");
                return Payability::Unknown;
            }
        };
        if let Err(why) = &resolved {
            warn!("payout address {address:?} cannot be paid: {why}");
        }
        lock(cache).insert(address, resolved.clone());
        resolved.into()
    }
}

impl From<Result<Vec<u8>, Unpayable>> for Payability {
    fn from(r: Result<Vec<u8>, Unpayable>) -> Self {
        match r {
            Ok(script) => Payability::Script(script),
            Err(why) => Payability::Unpayable(why),
        }
    }
}

/// Sort what the node returned for an address into a payable script or a reason it cannot be
/// paid. The output-size limit is applied here, at resolution, so the share path, the split
/// and the stats interface all read one answer per identity.
fn classify(resolved: Resolved) -> Result<Vec<u8>, Unpayable> {
    match resolved {
        Resolved::Script(script) if !output_script_size_is_valid(&script) => {
            Err(Unpayable::ScriptTooLong(script.len()))
        }
        Resolved::Script(script) => Ok(script),
        Resolved::Invalid => Err(Unpayable::NotAnAddress),
        Resolved::NoScript => Err(Unpayable::NoScript),
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
    // The pool receives the operator fee; what remains is split among the miners. The gateway
    // pays the fee to the pool's payout script as the coinbase remainder (the value minus these
    // dictated outputs), so no output is dictated for it here.
    let operator_fee = server.payout.fee_on(value);
    let miners_share = value - operator_fee;
    let (split, shares, work) = {
        let l = lock(&server.ledger);
        (
            l.split(miners_share, server.payout.min_payout, messages::MAX_COINBASER_OUTPUTS),
            l.len(),
            l.total_work(),
        )
    };
    let mut outputs = Vec::with_capacity(split.len());
    for (identity, amount) in split {
        // An identity is resolved on the share that first credits it, so all of these are
        // cached and this loop makes no RPC call in the ordinary case. Anything but a script
        // (the node is unreachable, or the identity was credited before this check existed
        // and is not payable) leaves its amount out of the dictated outputs, and the gateway
        // pays that amount to the pool's payout script as part of the remainder.
        match Resolver::payability(&server.resolver, node, &identity) {
            Payability::Script(script) => outputs.push(CoinbaseOutput { value: amount, script }),
            Payability::Unpayable(why) => warn!(
                "      {identity} cannot be paid ({why}); paying the other outputs and \
                 leaving this identity's amount to the pool"
            ),
            Payability::Unknown => warn!(
                "      {identity} could not be resolved; paying the other outputs and \
                 leaving this identity's amount to the pool"
            ),
        }
    }
    (outputs, shares, work)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratum::datum::messages::ClientConfig;

    /// `payability` returns from its cache before calling the node, so the node client, which
    /// cannot connect, is never called for an address `resolved` names.
    fn server_with(
        shares: &[(&str, u64)],
        resolved: &[(&str, Result<Vec<u8>, Unpayable>)],
        min_payout: u64,
    ) -> Server {
        server_with_fee(shares, resolved, min_payout, 0)
    }

    fn server_with_fee(
        shares: &[(&str, u64)],
        resolved: &[(&str, Result<Vec<u8>, Unpayable>)],
        min_payout: u64,
        fee_bps: u16,
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
            payout: PayoutPolicy { min_payout, window_multiple: 8.0, window_floor: 1, fee_bps },
            config_payload: config.encode().unwrap(),
            policy: PoolPolicy::from_config(&config),
            open_connections: AtomicUsize::new(0),
            max_connections: 8,
            datum_port: 28915,
            advertise: None,
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
            &[("alice", Ok(p2wpkh(0xa1))), ("bob", Ok(p2wpkh(0xb2)))],
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
    fn a_fee_is_deducted_before_the_split_and_left_to_the_pool() {
        // fee_bps 100 is 1%: 10_000 of 1_000_000 is withheld, and 990_000 is split among the
        // miners. The dictated outputs total the split, not the value; the gateway pays the
        // 10_000 difference to the pool's payout script as the coinbase remainder.
        let server = server_with_fee(
            &[("alice", 3), ("bob", 1)],
            &[("alice", Ok(p2wpkh(0xa1))), ("bob", Ok(p2wpkh(0xb2)))],
            0,
            100,
        );
        let (outputs, _, _) = coinbaser_outputs(&server, 1_000_000);
        assert_eq!(
            outputs.iter().map(|o| (o.value, o.script.clone())).collect::<Vec<_>>(),
            vec![(742_500, p2wpkh(0xa1)), (247_500, p2wpkh(0xb2))]
        );
        let paid: u64 = outputs.iter().map(|o| o.value).sum();
        assert_eq!(paid, 990_000);
        // The pool keeps what the split did not distribute.
        assert_eq!(1_000_000 - paid, 10_000);
        assert!(outputs.iter().all(|o| o.script != POOL));
    }

    #[test]
    fn the_fee_is_rounded_down_so_the_operator_never_over_takes() {
        let with_bps = |bps| PayoutPolicy {
            min_payout: 0,
            window_multiple: 8.0,
            window_floor: 1,
            fee_bps: bps,
        };
        assert_eq!(with_bps(0).fee_on(1_000_000), 0, "no fee by default");
        assert_eq!(with_bps(50).fee_on(1_000_000), 5_000, "0.5%");
        // 100 (1%) is the highest fee `main` accepts.
        assert_eq!(with_bps(100).fee_on(1_000_000), 10_000);
        // 1% of 1 sat is 0.01 sat, rounded down to 0: the miner keeps it.
        assert_eq!(with_bps(100).fee_on(1), 0);
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
            &[("alice", Ok(p2wpkh(0xa1))), ("nonsense", Err(Unpayable::NotAnAddress))],
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
        // network rejects. `classify` applies the limit when the address is resolved, so the
        // identity is unpayable from that point on rather than being dropped per template.
        let long = vec![0x00; 35];
        assert!(!output_script_size_is_valid(&long));
        assert_eq!(classify(Resolved::Script(long)), Err(Unpayable::ScriptTooLong(35)));
        let server = server_with(
            &[("alice", 3), ("toolong", 1)],
            &[("alice", Ok(p2wpkh(0xa1))), ("toolong", Err(Unpayable::ScriptTooLong(35)))],
            0,
        );
        let (outputs, _, _) = coinbaser_outputs(&server, 1_000_000);
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].script, p2wpkh(0xa1));
    }

    #[test]
    fn classify_sorts_what_the_node_returns() {
        assert_eq!(classify(Resolved::Invalid), Err(Unpayable::NotAnAddress));
        assert_eq!(classify(Resolved::NoScript), Err(Unpayable::NoScript));
        assert_eq!(classify(Resolved::Script(p2wpkh(0xa1))), Ok(p2wpkh(0xa1)));
        // 42 bytes: what validateaddress returns for a future witness version, over the
        // 34-byte coinbase output limit but under the 64-byte CoinbaserResponse field.
        assert_eq!(classify(Resolved::Script(vec![0x00; 42])), Err(Unpayable::ScriptTooLong(42)));
        // An OP_RETURN script may be 83 bytes.
        assert!(classify(Resolved::Script(vec![ratum::bitcoin::OP_RETURN; 83])).is_ok());
        assert_eq!(
            classify(Resolved::Script(vec![ratum::bitcoin::OP_RETURN; 84])),
            Err(Unpayable::ScriptTooLong(84))
        );
    }

    #[test]
    fn a_cached_answer_is_returned_without_asking_the_node() {
        // The node client in these tests cannot connect, so an uncached identity is `Unknown`
        // rather than unpayable: an RPC failure must not reject an identity that is valid.
        let server = server_with(&[], &[("alice", Ok(p2wpkh(0xa1)))], 0);
        assert!(matches!(
            Resolver::payability(&server.resolver, &server.node, "alice"),
            Payability::Script(s) if s == p2wpkh(0xa1)
        ));
        assert!(matches!(
            Resolver::payability(&server.resolver, &server.node, "unseen"),
            Payability::Unknown
        ));
        // An unresolvable identity is not cached, so the next call asks the node again.
        assert!(Resolver::cached(&server.resolver, "unseen").is_none());
    }

    #[test]
    fn the_minimum_is_applied_before_addresses_are_resolved() {
        // The small miner is removed from the split and its work leaves the denominator, so the
        // large one takes the whole value, not 999_000.
        let server = server_with(
            &[("large", 999), ("small", 1)],
            &[("large", Ok(p2wpkh(0xa1))), ("small", Ok(p2wpkh(0xb2)))],
            10_000,
        );
        let (outputs, shares, _) = coinbaser_outputs(&server, 1_000_000);
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].value, 1_000_000);
        // Still in the window and counted, but unpaid.
        assert_eq!(shares, 2);
    }
}
