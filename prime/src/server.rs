use crate::abw::AbwManager;
use log::{debug, error, info, warn};
use mio::Waker;
use ratum::bitcoin::output_script_size_is_valid;
use ratum::datum::handshake::KeyPairs;
use ratum::datum::messages::{self, CoinbaseOutput};
use ratum::{lock, rpc};
use ratum_prime::bounded::BoundedMap;
use ratum_prime::ledger::{Ledger, OwedBlock};
use ratum_prime::verify::{PoolPolicy, ReplayGuard, Splits};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
pub(crate) struct NodeView {
    pub(crate) tip: Mutex<Option<rpc::Tip>>,
    pub(crate) coinbase_value: Mutex<Option<u64>>,
    pub(crate) next_bits: Mutex<Option<u32>>,
    pub(crate) tip_history: Mutex<VecDeque<(u32, u64)>>,
    wakers: Mutex<Vec<Arc<Waker>>>,
}

pub(crate) const TIP_HISTORY_CAP: usize = 64;

impl NodeView {
    pub(crate) fn add_waker(&self, waker: &Arc<Waker>) {
        lock(&self.wakers).push(Arc::clone(waker));
    }

    pub(crate) fn remove_waker(&self, waker: &Arc<Waker>) {
        lock(&self.wakers).retain(|w| !Arc::ptr_eq(w, waker));
    }

    fn record_tip(&self, t: &rpc::Tip) {
        info!(
            "node tip: height {} difficulty {} {} (chain {})",
            t.height,
            t.difficulty,
            hex::encode(ratum::bitcoin::reversed(&t.hash)),
            t.chain.name()
        );
        let mut history = lock(&self.tip_history);
        history.push_back((t.height, ratum::unix_now()));
        while history.len() > TIP_HISTORY_CAP {
            history.pop_front();
        }
    }

    fn wake_connections(&self) {
        for w in lock(&self.wakers).iter() {
            if let Err(e) = w.wake() {
                debug!("could not wake a gateway connection thread: {e}");
            }
        }
    }
}

fn exit_on_wrong_chain(t: &rpc::Tip, expected: Option<rpc::Chain>) {
    let Some(expected) = expected else { return };
    if t.chain == expected {
        return;
    }
    error!(
        "the node is on chain {} but this pool started on chain {} and its ledger holds {} \
         shares; exiting rather than credit shares of one chain to the ledger of another",
        t.chain.name(),
        expected.name(),
        expected.name()
    );
    std::process::exit(1);
}

fn refresh_next_block(node: &rpc::Client, view: &NodeView) -> bool {
    match node.next_block() {
        Ok(n) => {
            info!(
                "node template: the next coinbase may pay {} sats at bits {:#010x}",
                n.coinbase_value, n.bits
            );
            *lock(&view.coinbase_value) = Some(n.coinbase_value);
            *lock(&view.next_bits) = Some(n.bits);
            true
        }
        Err(e) => {
            warn!("could not read a template: {e}");
            *lock(&view.coinbase_value) = None;
            *lock(&view.next_bits) = None;
            false
        }
    }
}

pub(crate) fn watch_node(
    node: rpc::Client,
    view: Arc<NodeView>,
    interval: Duration,
    expected_chain: Option<rpc::Chain>,
) {
    let mut last: Option<[u8; 32]> = None;
    let mut have_template = false;
    let mut wait_for_blocks = true;
    loop {
        let height = match node.tip() {
            Ok(t) => {
                exit_on_wrong_chain(&t, expected_chain);
                let tip_changed = last != Some(t.hash);
                let previous_bits = *lock(&view.next_bits);
                if tip_changed {
                    view.record_tip(&t);
                    last = Some(t.hash);
                    have_template = false;
                }
                if !have_template {
                    have_template = refresh_next_block(&node, &view);
                }
                *lock(&view.tip) = Some(t);
                if tip_changed || *lock(&view.next_bits) != previous_bits {
                    view.wake_connections();
                }
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
    pub(crate) allowed_agents: Vec<String>,
    pub(crate) require_v3: bool,
    pub(crate) sessions: Mutex<SessionStore>,
    pub(crate) abw_reveal_after: Duration,
    pub(crate) node: rpc::Client,
    pub(crate) node_view: Arc<NodeView>,
    pub(crate) replay: Arc<Mutex<ReplayGuard>>,
    pub(crate) ledger: Mutex<Ledger>,
    pub(crate) resolver: Mutex<Resolver>,
    pub(crate) payout: PayoutPolicy,
    pub(crate) policy: PoolPolicy,
    pub(crate) config_payload: Vec<u8>,
    pub(crate) open_connections: AtomicUsize,
    pub(crate) max_connections: usize,
    pub(crate) datum_port: u16,
    pub(crate) advertise: Option<String>,
    pub(crate) public_gateway: Option<String>,
}

pub(crate) const SESSION_KEEP: Duration = Duration::from_secs(3600);
pub(crate) const MAX_SAVED_SESSIONS: usize = 4096;

pub(crate) struct SavedSession {
    pub(crate) state: SessionState,
    pub(crate) saved_at: Instant,
    pub(crate) held_since: Instant,
}

impl SavedSession {
    pub(crate) fn expired(&self, now: Instant) -> bool {
        now.duration_since(self.saved_at) > SESSION_KEEP
    }
}

pub(crate) struct SessionStore(BoundedMap<[u8; 32], SavedSession>);

impl Default for SessionStore {
    fn default() -> Self {
        Self(BoundedMap::new(MAX_SAVED_SESSIONS))
    }
}

impl SessionStore {
    pub(crate) fn save(&mut self, key: [u8; 32], session: SavedSession) {
        let saved_at = session.saved_at;
        self.0.retain(|_, s| !s.expired(saved_at));
        if self.0.get(&key).is_some_and(|kept| kept.held_since > session.held_since) {
            return;
        }
        self.0.insert(key, session);
    }

    pub(crate) fn take(&mut self, key: &[u8; 32]) -> Option<SavedSession> {
        self.0.remove(key)
    }
}

impl Server {
    pub(crate) fn config_payload_v3(&self, token: &messages::ResumeToken) -> Vec<u8> {
        messages::ClientConfigV3 {
            payout_script: self.policy.payout_script.clone(),
            prime_id: self.policy.prime_id,
            resume_token: *token,
            coinbase_tag: self.policy.coinbase_tag.clone(),
            min_difficulty: self.policy.min_difficulty,
            bulk_framing: true,
            abw_disabled: false,
        }
        .encode()
        .expect("the v1 config from the same policy encoded at startup")
    }

    pub(crate) fn resume_or_start(
        &self,
        client_key: [u8; 32],
        presented: Option<&messages::ResumeToken>,
        now: Instant,
    ) -> (SessionState, bool) {
        let saved = lock(&self.sessions).take(&client_key);
        if let (Some(presented), Some(saved)) = (presented, saved)
            && !saved.expired(now)
            && saved.state.token == *presented
        {
            let mut state = saved.state;
            state.abw.resumed(now);
            return (state, true);
        }
        let state = SessionState {
            token: messages::new_resume_token(self.policy.prime_id),
            abw: AbwManager::start(now, self.abw_reveal_after),
            splits: HashMap::new(),
            coinbaser_id: 0,
        };
        (state, false)
    }
}

pub(crate) struct SessionState {
    pub(crate) token: messages::ResumeToken,
    pub(crate) abw: AbwManager,
    pub(crate) splits: Splits,
    pub(crate) coinbaser_id: u8,
}

pub(crate) struct OpenConnectionGuard(pub(crate) Arc<Server>);

impl Drop for OpenConnectionGuard {
    fn drop(&mut self) {
        self.0.open_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy)]
pub(crate) struct PayoutPolicy {
    pub(crate) min_payout: u64,
    pub(crate) window_multiple: f64,
    pub(crate) window_floor: u128,
    pub(crate) fee_bps: u16,
}

impl PayoutPolicy {
    pub(crate) fn fee_on(&self, value: u64) -> u64 {
        (u128::from(value) * u128::from(self.fee_bps) / u128::from(ratum::BASIS_POINTS_PER_UNIT))
            as u64
    }

    pub(crate) fn miners_share(&self, value: u64) -> u64 {
        value - self.fee_on(value)
    }
}

pub(crate) fn split_after_fee(l: &Ledger, payout: &PayoutPolicy, value: u64) -> Vec<(String, u64)> {
    l.split(payout.miners_share(value), payout.min_payout, messages::MAX_COINBASER_OUTPUTS)
}

pub(crate) struct Resolver {
    scripts: BoundedMap<String, Result<Vec<u8>, Unpayable>>,
}

const MAX_CACHED_ADDRESSES: usize = 1 << 16;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Unpayable {
    NotAnAddress,
    NoScript,
    ScriptTooLong(usize),
}

impl std::fmt::Display for Unpayable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAnAddress => write!(f, "not a valid address"),
            Self::NoScript => write!(f, "an address the node returns no script for"),
            Self::ScriptTooLong(n) => {
                write!(f, "over the coinbase output limit ({n} bytes)")
            }
        }
    }
}

pub(crate) enum Payability {
    Script(Vec<u8>),
    Unpayable(Unpayable),
    Unknown,
}

impl Resolver {
    pub(crate) fn new() -> Self {
        Self { scripts: BoundedMap::new(MAX_CACHED_ADDRESSES) }
    }

    fn remember(&mut self, address: &str, script: Result<Vec<u8>, Unpayable>) {
        self.scripts.insert(address.to_string(), script);
    }

    pub(crate) fn cached(cache: &Mutex<Self>, address: &str) -> Option<Result<Vec<u8>, Unpayable>> {
        lock(cache).scripts.get(address).cloned()
    }

    pub(crate) fn payability(cache: &Mutex<Self>, node: &rpc::Client, address: &str) -> Payability {
        if let Some(known) = Self::cached(cache, address) {
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
        lock(cache).remember(address, resolved.clone());
        resolved.into()
    }
}

impl From<Result<Vec<u8>, Unpayable>> for Payability {
    fn from(r: Result<Vec<u8>, Unpayable>) -> Self {
        match r {
            Ok(script) => Self::Script(script),
            Err(why) => Self::Unpayable(why),
        }
    }
}

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

pub(crate) enum Resolved {
    Script(Vec<u8>),
    Invalid,
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

fn payable_entries(
    server: &Server,
    split: Vec<(String, u64)>,
    left_out: &str,
) -> Vec<(String, u64, Vec<u8>)> {
    let mut kept = Vec::with_capacity(split.len());
    for (identity, sats) in split {
        match Resolver::payability(&server.resolver, &server.node, &identity) {
            Payability::Script(script) => kept.push((identity, sats, script)),
            Payability::Unpayable(why) => warn!(
                "      {identity} cannot be paid ({why}); its {sats} sats are left out of \
                 {left_out} and stay with the pool"
            ),
            Payability::Unknown => warn!(
                "      {identity} could not be resolved; its {sats} sats are left out of \
                 {left_out} and stay with the pool"
            ),
        }
    }
    kept
}

pub(crate) fn dictated_outputs(
    server: &Server,
    value: u64,
) -> (Vec<(String, CoinbaseOutput)>, usize, u128) {
    let (split, shares, work) = {
        let l = lock(&server.ledger);
        (split_after_fee(&l, &server.payout, value), l.len(), l.total_work())
    };
    let outputs = payable_entries(server, split, "the dictated outputs")
        .into_iter()
        .map(|(identity, value, script)| (identity, CoinbaseOutput { value, script }))
        .collect();
    (outputs, shares, work)
}

pub(crate) fn owed_for_block(
    server: &Server,
    height: u32,
    block_hash: [u8; 32],
    value: u64,
    at: u64,
) -> Option<OwedBlock> {
    let split = split_after_fee(&lock(&server.ledger), &server.payout, value);
    let entries: Vec<(String, u64)> = payable_entries(server, split, "the owed record")
        .into_iter()
        .map(|(identity, sats, _)| (identity, sats))
        .collect();
    let total: u64 = entries.iter().map(|(_, sats)| *sats).sum();
    if total == 0 {
        return None;
    }
    Some(OwedBlock { at, height, block_hash, total, settled_at: None, entries })
}
