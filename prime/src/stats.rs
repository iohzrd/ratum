//! The stats interface: one JSON snapshot of the pool, the window, the miners in it, the blocks
//! found and what they owe.

use crate::ledger::IdentityState;
use crate::ledger::blocks::{ConfirmationReading, FoundBlock, OwedBlock};
use crate::ledger::split::{Payout, PublicGatewayFeeWork, SplitPolicy};
use crate::payout;
use crate::server::Server;
use ratum::hashrate::{self, HashrateHistory};
use ratum::http::{self, Method, Reply, Request};
use ratum::lock;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

const HASHRATE_SPAN_SECS: u64 = 10 * ratum::SECS_PER_MINUTE;

fn hashes_per_second(work: u128, secs: u64) -> f64 {
    ratum::hashrate::from_work(work, std::time::Duration::from_secs(secs))
}

const TARGET_BLOCK_SECS: f64 = 10.0 * ratum::SECS_PER_MINUTE as f64;
const RETARGET_TIMESPAN_SECS: f64 = 14.0 * ratum::SECS_PER_DAY as f64;
const RETARGET_INTERVAL: u32 = (RETARGET_TIMESPAN_SECS / TARGET_BLOCK_SECS) as u32;
const MAX_RETARGET_FACTOR: f64 = 4.0;

const RECENT_BLOCKS: usize = 50;

/// The start of the span every reported hashrate is measured over.
fn hashrate_cutoff() -> u64 {
    ratum::unix_now().saturating_sub(HASHRATE_SPAN_SECS)
}

fn pool_hashes_per_second(server: &Server) -> f64 {
    hashes_per_second(lock(&server.ledger).work_since(hashrate_cutoff()), HASHRATE_SPAN_SECS)
}

#[derive(Debug, PartialEq)]
struct Luck {
    percent: Option<f64>,
    blocks: u32,
}

fn luck(blocks: &[FoundBlock]) -> Luck {
    let mut expected = 0.0f64;
    let mut counted = 0u32;
    for pair in blocks.windows(2) {
        let (prev, b) = (&pair[0], &pair[1]);
        if b.network_difficulty > 0.0 && b.cumulative_work >= prev.cumulative_work {
            expected += (b.cumulative_work - prev.cumulative_work) as f64 / b.network_difficulty;
            counted += 1;
        }
    }
    if counted == 0 || expected <= 0.0 {
        return Luck { percent: None, blocks: 0 };
    }
    Luck { percent: Some(f64::from(counted) / expected * 100.0), blocks: counted }
}

pub fn spawn(server: Arc<Server>, listen: &str) -> Result<SocketAddr, String> {
    let http = http::Server::http(listen).map_err(|e| e.to_string())?;
    let addr = http.local_addr().map_err(|e| e.to_string())?;
    let history = Arc::new(Mutex::new(match server.settings.hashrate_path() {
        Some(path) => HashrateHistory::in_file(path),
        None => HashrateHistory::default(),
    }));
    let sampled = Arc::clone(&server);
    hashrate::sample_every("stats-sampler", Arc::clone(&history), move || {
        pool_hashes_per_second(&sampled)
    });
    // The interface serves GET only, so a request carrying a body is refused.
    http::serve("stats", http, 0, move |request| handle(&server, &history, &request));
    Ok(addr)
}

fn handle(server: &Server, history: &Mutex<HashrateHistory>, request: &Request) -> Reply {
    if request.method != Method::Get {
        return http::method_not_allowed();
    }
    let (path, _) = http::path_and_query(request);
    match path.as_str() {
        "/stats.json" => http::noindex(http::json(snapshot(server, history))),
        _ => http::not_found(),
    }
}

fn network_json(
    tip: Option<ratum::rpc::Tip>,
    coinbase_value: Option<u64>,
    observed_block_secs: Option<f64>,
) -> Value {
    let Some(t) = tip else {
        return json!({
            "chain": Value::Null,
            "tip_height": Value::Null,
            "tip_hash": Value::Null,
            "difficulty": Value::Null,
            "coinbase_value": coinbase_value,
        });
    };
    json!({
        "chain": t.chain.name(),
        "tip_height": t.height,
        "tip_hash": ratum::bitcoin::hash_to_display_hex(&t.hash),
        "difficulty": t.difficulty,
        "coinbase_value": coinbase_value,
        "observed_block_seconds": observed_block_secs,
        "retarget": {
            "height": (t.height / RETARGET_INTERVAL + 1) * RETARGET_INTERVAL,
            "blocks_remaining": RETARGET_INTERVAL - t.height % RETARGET_INTERVAL,
            "estimated_factor": observed_block_secs.map(|s| {
                (TARGET_BLOCK_SECS / s).clamp(1.0 / MAX_RETARGET_FACTOR, MAX_RETARGET_FACTOR)
            }),
        },
    })
}

/// What `confirmations` shows for a block the node answered it stores no block for: the count
/// the node answers for a block off its best chain, since the best chain does not hold it
/// either, in place of the value the ledger stores for it.
const NOT_STORED_SHOWN_AS: i64 = -1;

fn confirmations_json(
    state: Option<&ConfirmationReading>,
    height: u32,
    tip_height: Option<u32>,
) -> Value {
    match (state, tip_height) {
        (Some(s), _) if !s.node_stores_block() => json!(NOT_STORED_SHOWN_AS),
        (Some(s), _) if !s.on_best_chain() => json!(s.confirmations),
        (_, Some(tip)) if tip >= height => json!(i64::from(tip) - i64::from(height) + 1),
        (Some(s), _) => json!(s.confirmations),
        (None, _) => Value::Null,
    }
}

struct OwedJson {
    unsettled_sats: u64,
    by_identity: Vec<Value>,
    blocks: Vec<Value>,
}

fn owed_json(
    owed: &[OwedBlock],
    confirmations: &HashMap<[u8; 32], ConfirmationReading>,
    tip_height: Option<u32>,
) -> OwedJson {
    let mut unsettled_sats: u64 = 0;
    let mut unsettled_per_identity: HashMap<String, u64> = HashMap::new();
    let blocks: Vec<Value> = owed
        .iter()
        .map(|o| {
            if o.settled_at.is_none() {
                unsettled_sats += o.total();
                for p in &o.entries {
                    *unsettled_per_identity.entry(p.identity.clone()).or_insert(0) += p.sats;
                }
            }
            json!({
                "height": o.height,
                "block_hash": hex::encode(o.block_hash),
                "found_at": o.found_at,
                "total_sats": o.total(),
                "settled_at": o.settled_at,
                "confirmations": confirmations_json(confirmations.get(&o.block_hash), o.height, tip_height),
                "miners": o.entries.iter().map(|p| {
                    json!({ "identity": p.identity, "sats": p.sats })
                }).collect::<Vec<_>>(),
            })
        })
        .collect();
    let mut ranked: Vec<Payout> = unsettled_per_identity
        .into_iter()
        .map(|(identity, sats)| Payout { identity, sats })
        .collect();
    ranked.sort_by(|a, b| b.sats.cmp(&a.sats).then_with(|| a.identity.cmp(&b.identity)));
    let by_identity =
        ranked.into_iter().map(|p| json!({ "identity": p.identity, "sats": p.sats })).collect();
    OwedJson { unsettled_sats, by_identity, blocks }
}

fn miners_json(server: &Server, l: &LedgerView) -> Vec<Value> {
    let chain = server.share_policy.chain;
    l.miners
        .iter()
        .map(|m| {
            let work = m.state.work;
            let share_percent =
                if l.total_work > 0 { work as f64 / l.total_work as f64 * 100.0 } else { 0.0 };
            let payable = payout::address_script(&m.identity, chain).is_some();
            let unpayable_reason = (!payable).then(|| payout::unpayable_reason(chain));
            json!({
                "identity": m.identity,
                "work": work.to_string(),
                "share_percent": share_percent,
                "hashrate_hs": hashes_per_second(m.recent_work, HASHRATE_SPAN_SECS),
                "payout_sats": m.payout_sats,
                "payable": payable,
                "unpayable_reason": unpayable_reason,
                "tag": m.state.tag_secondary,
                "own_gateway_work": m.state.own_gateway_work.to_string(),
            })
        })
        .collect()
}

fn public_gateway_fee_json(l: &LedgerView, coinbase_value: Option<u64>) -> Value {
    let (Some(gateway), Some(work)) = (
        l.split_policy.public_gateway.as_ref().filter(|g| g.fee_bps > 0),
        l.public_gateway_fee_work,
    ) else {
        return Value::Null;
    };
    let miners_value = coinbase_value.map_or(0, |v| l.split_policy.miners_share(v));
    let sats_for = |work: u128| {
        u128::from(miners_value).saturating_mul(work).checked_div(l.total_work).unwrap_or(0) as u64
    };
    json!({
        "fee_bps": gateway.fee_bps,
        "subsidy_bps": gateway.subsidy_bps,
        "public_gateway_tag": gateway.tag,
        "public_gateway_work": work.public_gateway_work.to_string(),
        "fee_work": work.fee_work.to_string(),
        "fee_sats": sats_for(work.fee_work),
        "reassigned_work": work.reassigned_work.to_string(),
        "reassigned_sats": sats_for(work.reassigned_work),
        "own_gateway_work": work.own_gateway_work.to_string(),
    })
}

/// One miner's row of the window, joined once in `LedgerView::read`: its state from the
/// ledger's identity map, what the split would pay it at the current coinbase value, and its
/// work over the hashrate span. The three come from three queries keyed by identity, so
/// pairing them here is what keeps `miners_json` free of per-row lookups.
struct MinerRow {
    identity: String,
    state: IdentityState,
    payout_sats: u64,
    recent_work: u128,
}

struct LedgerView {
    total_work: u128,
    target_work: u128,
    shares: usize,
    max_shares: usize,
    /// Whether the count bound, not `target_work`, is what ends the window. The window then
    /// spans less work than the policy asks for and never reaches `target_work`.
    count_capped: bool,
    /// Most work first, as `Ledger::identities` orders them.
    miners: Vec<MinerRow>,
    owed: Vec<OwedBlock>,
    /// The newest `RECENT_BLOCKS` blocks alone: the rest of the history is read under the
    /// records lock into `luck` and `blocks_found`, so a request copies a bounded amount.
    recent_blocks: Vec<FoundBlock>,
    blocks_found: usize,
    luck: Luck,
    confirmations: HashMap<[u8; 32], ConfirmationReading>,
    recent_work: u128,
    window_multiple: f64,
    split_policy: SplitPolicy,
    public_gateway_fee_work: Option<PublicGatewayFeeWork>,
}

impl LedgerView {
    fn read(server: &Server, coinbase_value: Option<u64>) -> Self {
        let (owed, recent_blocks, blocks_found, luck, confirmations) = {
            let r = lock(&server.records);
            let blocks = r.blocks();
            let recent_blocks = blocks[blocks.len().saturating_sub(RECENT_BLOCKS)..].to_vec();
            let confirmations = r
                .owed()
                .iter()
                .map(|o| o.block_hash)
                .chain(recent_blocks.iter().map(|b| b.block_hash))
                .filter_map(|hash| r.confirmations(&hash).map(|state| (hash, state)))
                .collect();
            (r.owed().to_vec(), recent_blocks, blocks.len(), luck(blocks), confirmations)
        };
        let l = lock(&server.ledger);
        let mut recent = l.work_since_by_identity(hashrate_cutoff());
        let recent_work = recent.values().sum();
        let mut payout_sats: HashMap<String, u64> = l
            .split(coinbase_value.unwrap_or(0))
            .into_iter()
            .map(|p| (p.identity, p.sats))
            .collect();
        let miners = l
            .identities()
            .into_iter()
            .map(|(identity, state)| MinerRow {
                payout_sats: payout_sats.remove(&identity).unwrap_or(0),
                recent_work: recent.remove(&identity).unwrap_or(0),
                identity,
                state,
            })
            .collect();
        Self {
            total_work: l.total_work(),
            target_work: l.window(),
            shares: l.len(),
            max_shares: l.max_shares(),
            count_capped: l.count_capped(),
            miners,
            window_multiple: l.window_rule().multiple,
            split_policy: l.split_policy().clone(),
            public_gateway_fee_work: l.public_gateway_fee_work(),
            owed,
            recent_blocks,
            blocks_found,
            luck,
            confirmations,
            recent_work,
        }
    }
}

/// `blocks` newest first. The caller passes the newest `RECENT_BLOCKS` alone.
fn recent_blocks_json(
    blocks: &[FoundBlock],
    confirmations: &HashMap<[u8; 32], ConfirmationReading>,
    tip_height: Option<u32>,
) -> Vec<Value> {
    blocks
        .iter()
        .rev()
        .map(|b| {
            json!({
                "height": b.height,
                "block_hash": hex::encode(b.block_hash),
                "found_at": b.found_at,
                "paid_to_split": b.paid_to_split,
                "paid_to_pool": b.paid_to_pool,
                "finder": b.finder,
                "tag": b.tag_secondary,
                "confirmations": confirmations_json(confirmations.get(&b.block_hash), b.height, tip_height),
            })
        })
        .collect()
}

fn snapshot(server: &Server, history: &Mutex<HashrateHistory>) -> Value {
    let (tip, template) = server.node_state.tip_and_template();
    let tip_height = tip.as_ref().map(|t| t.height);
    let coinbase_value = template.map(|t| t.coinbase_value);
    let l = LedgerView::read(server, coinbase_value);
    let operator_fee = coinbase_value.map_or(0, |v| l.split_policy.fee_on(v));
    let public_gateway_fee = l.split_policy.public_gateway.as_ref();

    let owed = owed_json(&l.owed, &l.confirmations, tip_height);
    let miners = miners_json(server, &l);
    let public_gateway_fee_detail = public_gateway_fee_json(&l, coinbase_value);
    let network = network_json(tip, coinbase_value, server.node_state.observed_block_seconds());
    let pool_hs = hashes_per_second(l.recent_work, HASHRATE_SPAN_SECS);

    json!({
        "pool": {
            "motd": server.settings.motd,
            "version": crate::VERSION,
            "coinbase_tag": server.share_policy.config.coinbase_tag,
            "prime_id": server.share_policy.config.prime_id,
            "payout_script": hex::encode(&server.share_policy.config.payout_script),
            "fee_bps": l.split_policy.fee_bps,
            "public_gateway_fee_bps": public_gateway_fee.map_or(0, |f| f.fee_bps),
            "public_gateway_fee_subsidy_bps": public_gateway_fee.map_or(0, |f| f.subsidy_bps),
            "min_payout": crate::ledger::split::MIN_PAYOUT,
            "window_multiple": l.window_multiple,
            "min_difficulty": server.share_policy.config.min_difficulty,
            "datum_port": server.settings.datum_port(),
            "pubkey": server.pool_keys.public().to_hex(),
        },
        "network": network,
        "connections": {
            "open": server.open_connections.load(Ordering::Relaxed),
            "max": server.settings.max_connections,
        },
        "hashrate": {
            "span_seconds": HASHRATE_SPAN_SECS,
            "pool_hs": pool_hs,
            "network_hs": server.node_state.mining.network_hashps(),
            "pool_share": server.node_state.mining.network_share(pool_hs),
            "interval_seconds": hashrate::INTERVAL_SECS,
            "history": lock(history).json(),
        },
        "window": {
            "work": l.total_work.to_string(),
            "target_work": l.target_work.to_string(),
            "shares": l.shares,
            "max_shares": l.max_shares,
            "count_capped": l.count_capped,
            "operator_fee_sats": operator_fee,
            "miners": miners,
        },
        "public_gateway_fee": public_gateway_fee_detail,
        "owed": {
            "unsettled_sats": owed.unsettled_sats,
            "by_identity": owed.by_identity,
            "blocks": owed.blocks,
        },
        "blocks": {
            "found": l.blocks_found,
            "luck_percent": l.luck.percent,
            "luck_blocks": l.luck.blocks,
            "recent": recent_blocks_json(&l.recent_blocks, &l.confirmations, tip_height),
        },
        "node_warnings": server.node_state.mining.warnings(),
        "generated_at": ratum::unix_now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{ALICE, hash, server_with, share};

    /// The window figures a reader uses to distinguish a window still filling from one that
    /// has reached its share count bound.
    #[test]
    fn the_window_reports_its_share_count_against_the_bound_it_stops_at() {
        const CAP: usize = 8;
        let server = server_with(&[]);
        let history = Mutex::new(HashrateHistory::default());

        lock(&server.ledger).set_max_shares(CAP);
        for i in 0..4u64 {
            lock(&server.ledger).record(share(1_000 + i, ALICE, 16, hash(i), "")).unwrap();
        }
        let window = snapshot(&server, &history)["window"].clone();
        assert_eq!(window["shares"], json!(4));
        assert_eq!(window["max_shares"], json!(CAP));
        assert_eq!(window["count_capped"], json!(false), "still filling towards the target");

        for i in 4..(CAP as u64 + 4) {
            lock(&server.ledger).record(share(1_000 + i, ALICE, 16, hash(i), "")).unwrap();
        }
        let window = snapshot(&server, &history)["window"].clone();
        assert_eq!(window["shares"], json!(CAP));
        assert_eq!(window["count_capped"], json!(true), "the count bound ends the window");
        assert_eq!(
            window["work"],
            json!((CAP as u128 * 16).to_string()),
            "which is less work than the target, and no further share adds to it"
        );
    }

    fn block(n: u8, cumulative_work: u128, network_difficulty: f64) -> FoundBlock {
        FoundBlock {
            found_at: u64::from(n),
            height: u32::from(n),
            block_hash: [n; 32],
            paid_to_split: 0,
            paid_to_pool: 0,
            finder: "a".into(),
            tag_secondary: String::new(),
            network_difficulty,
            cumulative_work,
        }
    }

    #[test]
    fn luck_is_found_over_expected_between_consecutive_blocks() {
        let blocks = [block(1, 0, 100.0), block(2, 100, 100.0), block(3, 300, 100.0)];
        let luck = luck(&blocks);
        assert_eq!(luck.blocks, 2, "the span before the first block has no start mark");
        assert!((luck.percent.unwrap() - 2.0 / 3.0 * 100.0).abs() < 1e-9);
    }

    #[test]
    fn luck_needs_two_blocks_and_skips_unusable_spans() {
        let none = Luck { percent: None, blocks: 0 };
        assert_eq!(luck(&[]), none);
        assert_eq!(luck(&[block(1, 100, 100.0)]), none);
        let broken = [block(1, 0, 0.0), block(2, 100, 0.0)];
        assert_eq!(luck(&broken), none);
        let reset = [block(1, 500, 100.0), block(2, 100, 100.0)];
        assert_eq!(luck(&reset), none);
    }
    #[test]
    fn confirmations_are_the_depth_below_the_tip_unless_the_last_reading_left_the_chain() {
        let read = |confirmations: i64| ConfirmationReading { checked_at: 1, confirmations };
        assert_eq!(confirmations_json(None, 971_765, Some(972_091)), json!(327));
        assert_eq!(confirmations_json(Some(&read(100)), 971_765, Some(972_091)), json!(327));
        assert_eq!(confirmations_json(Some(&read(100)), 971_765, None), json!(100));
        assert_eq!(confirmations_json(Some(&read(-1)), 971_765, Some(972_091)), json!(-1));
        assert_eq!(
            confirmations_json(
                Some(&read(ConfirmationReading::NOT_STORED)),
                971_765,
                Some(972_091)
            ),
            json!(-1),
            "a block the node does not store is shown off the best chain"
        );
        assert_eq!(confirmations_json(None, 971_765, None), Value::Null);
        assert_eq!(
            confirmations_json(Some(&read(3)), 971_765, Some(971_760)),
            json!(3),
            "a tip behind the block leaves the reading in place"
        );
    }
}
