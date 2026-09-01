//! A read-only HTTP interface: a JSON snapshot of the pool's state at `/stats.json` and a
//! single page at `/` that fetches and renders it. It reads the same `Arc<Server>` the
//! connection threads share and serves only GET; its one write is the hashrate history it
//! samples once a minute for the page's chart, so it adds no way to change the pool. It is
//! started only when `--stats-listen` names an address; bind it to `127.0.0.1` unless it
//! is behind a reverse proxy, since the page is unauthenticated.

use crate::server::{Resolver, Server, split_after_fee, unix_now};
use log::warn;
use ratum::http;
use ratum::lock;
use ratum_prime::ledger::FoundBlock;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, LazyLock, Mutex};
use tiny_http::{Method, Request, Server as HttpServer};

static INDEX_HTML: LazyLock<String> =
    LazyLock::new(|| ratum::web::assemble(include_str!("stats.html")));

/// The span the hashrate estimate averages over. Long enough that a miner at the minimum
/// share difficulty has several shares accepted within it; short enough that the estimate
/// reflects a rig starting or stopping within minutes.
const HASHRATE_SPAN_SECS: u64 = 600;

/// Expected hashes per unit of share difficulty: difficulty 1 is the 0x1d00ffff target,
/// 2^32 hashes on average. The BLAKE2b fork keeps the compact-target encoding, so the
/// constant is unchanged.
const HASHES_PER_DIFFICULTY: f64 = 4_294_967_296.0;

/// `work` difficulty units over `secs` seconds as hashes per second.
fn hashes_per_second(work: u128, secs: u64) -> f64 {
    if secs == 0 {
        return 0.0;
    }
    work as f64 * HASHES_PER_DIFFICULTY / secs as f64
}

/// Blocks per difficulty period and the block spacing the chain targets, for the retarget
/// estimate. The next adjustment is at the next multiple of the interval, and the factor is
/// the target spacing over the observed spacing, bounded to the consensus limit of 4 either
/// way.
const RETARGET_INTERVAL: u32 = 2016;
const TARGET_BLOCK_SECS: f64 = 600.0;

/// How many of the newest recorded blocks the snapshot lists.
const RECENT_BLOCKS: usize = 50;

/// The pool-hashrate history the snapshot serves for the page's chart: one sample per
/// interval, kept in memory for a day. It begins when the stats interface starts, so a
/// restart shows as a gap in the chart.
const HISTORY_INTERVAL_SECS: u64 = 60;
const HISTORY_CAP: usize = 24 * 60;

/// Append one sample and discard the oldest beyond the cap.
fn push_sample(history: &mut VecDeque<(u64, f64)>, at: u64, hs: f64) {
    history.push_back((at, hs));
    while history.len() > HISTORY_CAP {
        history.pop_front();
    }
}

/// The sample ring, owned by `spawn`: the sampler thread appends and the snapshot reads,
/// and the rest of the pool has no use for it.
type HashrateHistory = Arc<Mutex<VecDeque<(u64, f64)>>>;

/// Record the hashrate estimate as of now: the same figure the snapshot computes on
/// request, from the shares accepted in the last `HASHRATE_SPAN_SECS`.
fn sample_hashrate(server: &Server, history: &Mutex<VecDeque<(u64, f64)>>) {
    let now = unix_now();
    let (work, _) = lock(&server.ledger).work_since(now.saturating_sub(HASHRATE_SPAN_SECS));
    push_sample(&mut lock(history), now, hashes_per_second(work, HASHRATE_SPAN_SECS));
}

/// Blocks found per block expected, as a percent, over the recorded block history: for each
/// pair of consecutive records, the work between them over the difficulty at the later one
/// is the blocks expected in that span. The span before the first record has no start mark,
/// so measurement begins there; `None` until two blocks are recorded. Also returns how many
/// found blocks the figure covers.
fn luck_percent(blocks: &[FoundBlock]) -> (Option<f64>, u32) {
    let mut expected = 0.0f64;
    let mut counted = 0u32;
    for pair in blocks.windows(2) {
        let (prev, b) = (&pair[0], &pair[1]);
        // A record with no difficulty (the tip was unknown at acceptance) or a counter
        // reset (a ledger replaced under a kept history) cannot contribute a span.
        if b.difficulty > 0.0 && b.cumulative_work >= prev.cumulative_work {
            expected += (b.cumulative_work - prev.cumulative_work) as f64 / b.difficulty;
            counted += 1;
        }
    }
    if counted == 0 || expected <= 0.0 {
        return (None, 0);
    }
    (Some(f64::from(counted) / expected * 100.0), counted)
}

/// Bind `listen` and serve the stats interface on a thread. Returns the bound address (so a
/// `:0` port resolves to the real one) or an error if the address cannot be bound, which the
/// caller reports; the pool keeps running either way.
pub(crate) fn spawn(server: Arc<Server>, listen: &str) -> Result<SocketAddr, String> {
    let http = HttpServer::http(listen).map_err(|e| e.to_string())?;
    let addr = http.server_addr().to_ip().ok_or("no socket address")?;
    // The chart's history: one sample now, so the snapshot never serves an empty list,
    // then one per interval from a thread of its own.
    let history: HashrateHistory = Arc::new(Mutex::new(VecDeque::new()));
    sample_hashrate(&server, &history);
    let (sampler, sampler_history) = (Arc::clone(&server), Arc::clone(&history));
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(HISTORY_INTERVAL_SECS));
            sample_hashrate(&sampler, &sampler_history);
        }
    });
    http::serve("stats", http, move |request| {
        if let Err(e) = handle(&server, &history, request) {
            warn!("stats: could not send a response: {e}");
        }
    });
    Ok(addr)
}

fn handle(
    server: &Server,
    history: &Mutex<VecDeque<(u64, f64)>>,
    request: Request,
) -> std::io::Result<()> {
    if *request.method() != Method::Get {
        return request.respond(http::method_not_allowed());
    }
    // The paths carry no parameters.
    let (path, _) = http::path_and_query(&request);
    match path.as_str() {
        "/" | "/index.html" => request.respond(http::html(INDEX_HTML.clone())),
        "/stats.json" => {
            request.respond(http::body(snapshot(server, history), "application/json"))
        }
        _ => request.respond(http::not_found()),
    }
}

/// The JSON snapshot. Every field is read from the shared state; no secret (the node
/// credentials, the pool signing key) is included. `work` values are `u128`, which JSON
/// numbers cannot hold in full, so they are strings.
fn snapshot(server: &Server, history: &Mutex<VecDeque<(u64, f64)>>) -> String {
    let tip = *lock(&server.node_view.tip);
    let coinbase_value = *lock(&server.node_view.coinbase_value);
    let operator_fee = coinbase_value.map_or(0, |v| server.payout.fee_on(v));

    let hashrate_cutoff = unix_now().saturating_sub(HASHRATE_SPAN_SECS);
    let (total_work, target_work, shares, work_by_identity, split, owed, recent, blocks) = {
        let l = lock(&server.ledger);
        (
            l.total_work(),
            l.window(),
            l.len(),
            l.work_by_identity(),
            split_after_fee(&l, &server.payout, coinbase_value.unwrap_or(0)),
            l.owed().to_vec(),
            l.work_since(hashrate_cutoff),
            l.blocks().to_vec(),
        )
    };
    let payout_sats: HashMap<String, u64> = split.into_iter().collect();
    let (recent_work, recent_by_identity) = recent;

    // The recorded block history: the newest for the page's table, and the luck figure over
    // the whole record.
    let (luck, luck_blocks) = luck_percent(&blocks);
    let recent_blocks: Vec<serde_json::Value> = blocks
        .iter()
        .rev()
        .take(RECENT_BLOCKS)
        .map(|b| {
            serde_json::json!({
                "height": b.height,
                "block_hash": hex::encode(b.block_hash),
                "found_at": b.at,
                "paid_to_split": b.paid_to_split,
                "paid_to_pool": b.paid_to_pool,
                "finder": b.finder,
            })
        })
        .collect();

    // The observed block spacing, from the span of tip changes the node watcher has seen
    // (at most `TIP_HISTORY_CAP`); `None` until it has seen two. A reorg can lower the
    // later height, which the guard discards rather than divides by.
    let observed_block_secs = {
        let tips = lock(&server.node_view.tip_history);
        match (tips.front(), tips.back()) {
            (Some(&(h0, t0)), Some(&(h1, t1))) if h1 > h0 && t1 > t0 => {
                Some((t1 - t0) as f64 / f64::from(h1 - h0))
            }
            _ => None,
        }
    };

    // Blocks whose coinbase paid the window nothing: what the pool's payout script received
    // that the window is owed, per block and summed per identity while unsettled. Settlement
    // is a wallet transaction the operator records with --settle-block.
    let mut owed_unsettled: u64 = 0;
    let mut owed_by_identity: HashMap<String, u64> = HashMap::new();
    let owed_blocks: Vec<serde_json::Value> = owed
        .iter()
        .map(|o| {
            if o.settled_at.is_none() {
                owed_unsettled += o.total;
                for (identity, sats) in &o.entries {
                    *owed_by_identity.entry(identity.clone()).or_insert(0) += sats;
                }
            }
            serde_json::json!({
                "height": o.height,
                "block_hash": hex::encode(o.block_hash),
                "found_at": o.at,
                "total_sats": o.total,
                "settled_at": o.settled_at,
                "miners": o.entries.iter().map(|(identity, sats)| {
                    serde_json::json!({ "identity": identity, "sats": sats })
                }).collect::<Vec<_>>(),
            })
        })
        .collect();
    let mut owed_by_identity: Vec<(String, u64)> = owed_by_identity.into_iter().collect();
    owed_by_identity.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let owed_by_identity: Vec<serde_json::Value> = owed_by_identity
        .into_iter()
        .map(|(identity, sats)| serde_json::json!({ "identity": identity, "sats": sats }))
        .collect();

    let miners: Vec<serde_json::Value> = work_by_identity
        .iter()
        .map(|(identity, work)| {
            let share_percent =
                if total_work > 0 { *work as f64 / total_work as f64 * 100.0 } else { 0.0 };
            // Read-through of the resolver cache only: an unauthenticated request must not
            // make the pool call the node. Every identity credited since the pool started was
            // resolved on its first share, so `null` is an identity read back from the ledger
            // at startup that has not submitted since.
            let (payable, unpayable_reason) = match Resolver::cached(&server.resolver, identity) {
                Some(Ok(_)) => (Some(true), None),
                Some(Err(why)) => (Some(false), Some(why.to_string())),
                None => (None, None),
            };
            serde_json::json!({
                "identity": identity,
                "work": work.to_string(),
                "share_percent": share_percent,
                // Approximate, from the shares accepted from this identity in the last
                // `hashrate.span_seconds`: zero for one idle that long.
                "hashrate_hs": hashes_per_second(
                    recent_by_identity.get(identity).copied().unwrap_or(0),
                    HASHRATE_SPAN_SECS,
                ),
                // What the split allocates. An identity that is not payable is not paid it:
                // the amount is left in the coinbase remainder, which the gateway pays to the
                // pool's payout script.
                "payout_sats": payout_sats.get(identity).copied().unwrap_or(0),
                "payable": payable,
                "unpayable_reason": unpayable_reason,
            })
        })
        .collect();

    let network = match &tip {
        Some(t) => serde_json::json!({
            "chain": t.chain.name(),
            "tip_height": t.height,
            "tip_hash": hex::encode(ratum::bitcoin::reversed(&t.hash)),
            "difficulty": t.difficulty,
            "coinbase_value": coinbase_value,
            "observed_block_seconds": observed_block_secs,
            "retarget": {
                "height": (t.height / RETARGET_INTERVAL + 1) * RETARGET_INTERVAL,
                "blocks_remaining": RETARGET_INTERVAL - t.height % RETARGET_INTERVAL,
                "estimated_factor": observed_block_secs
                    .map(|s| (TARGET_BLOCK_SECS / s).clamp(0.25, 4.0)),
            },
        }),
        None => serde_json::json!({
            "chain": serde_json::Value::Null,
            "tip_height": serde_json::Value::Null,
            "tip_hash": serde_json::Value::Null,
            "difficulty": serde_json::Value::Null,
            "coinbase_value": coinbase_value,
        }),
    };

    let snapshot = serde_json::json!({
        "pool": {
            "motd": server.motd,
            // The build this pool is running: the package version and the git commit.
            "version": ratum::VERSION,
            "coinbase_tag": server.policy.coinbase_tag,
            "prime_id": server.policy.prime_id,
            "payout_script": hex::encode(&server.policy.payout_script),
            "fee_bps": server.payout.fee_bps,
            "min_payout": server.payout.min_payout,
            "window_multiple": server.payout.window_multiple,
            "min_difficulty": server.policy.min_difficulty,
            // What a gateway needs to connect: the pool's DATUM port and its public key. The
            // public key is not a secret; the pool logs it and every gateway is given it.
            // `advertise` is the operator-set host (or host:port), or null to use the address
            // the page was reached on.
            "datum_port": server.datum_port,
            "pubkey": server.pool_keys.pubkey_hex(),
            "advertise": server.advertise,
        },
        "network": network,
        "connections": {
            "open": server.open_connections.load(Ordering::Relaxed),
            "max": server.max_connections,
        },
        // Approximate, from accepted-share difficulty over the span: work that was not
        // accepted as a share (stale or rejected work, a rig's partial interval) is not
        // counted.
        "hashrate": {
            "span_seconds": HASHRATE_SPAN_SECS,
            "pool_hs": hashes_per_second(recent_work, HASHRATE_SPAN_SECS),
            // `[unix_seconds, hashes_per_second]` pairs, oldest first, one per
            // `interval_seconds`. Whole hashes per second: the fraction carries nothing.
            "interval_seconds": HISTORY_INTERVAL_SECS,
            "history": lock(history)
                .iter()
                .map(|&(t, hs)| serde_json::json!([t, hs as u64]))
                .collect::<Vec<_>>(),
        },
        "window": {
            "work": total_work.to_string(),
            "target_work": target_work.to_string(),
            "shares": shares,
            "operator_fee_sats": operator_fee,
            "miners": miners,
        },
        "owed": {
            "unsettled_sats": owed_unsettled,
            "by_identity": owed_by_identity,
            "blocks": owed_blocks,
        },
        // The recorded block history begins when this pool version first ran; blocks found
        // before that are not listed and not in the luck figure.
        "blocks": {
            "found": blocks.len(),
            "luck_percent": luck,
            "luck_blocks": luck_blocks,
            "recent": recent_blocks,
        },
        "generated_at": unix_now(),
    });
    snapshot.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(n: u8, cumulative_work: u128, difficulty: f64) -> FoundBlock {
        FoundBlock {
            at: u64::from(n),
            height: u32::from(n),
            block_hash: [n; 32],
            paid_to_split: 0,
            paid_to_pool: 0,
            finder: "a".into(),
            difficulty,
            cumulative_work,
        }
    }

    #[test]
    fn luck_is_found_over_expected_between_consecutive_blocks() {
        // Spans of 100 and 200 work at difficulty 100: 1 and 2 blocks expected, 2 found.
        let blocks = [block(1, 0, 100.0), block(2, 100, 100.0), block(3, 300, 100.0)];
        let (luck, counted) = luck_percent(&blocks);
        assert_eq!(counted, 2, "the span before the first block has no start mark");
        assert!((luck.unwrap() - 2.0 / 3.0 * 100.0).abs() < 1e-9);
    }

    #[test]
    fn luck_needs_two_blocks_and_skips_unusable_spans() {
        assert_eq!(luck_percent(&[]), (None, 0));
        assert_eq!(luck_percent(&[block(1, 100, 100.0)]), (None, 0));
        // A record with no difficulty, and one whose counter decreased (a replaced
        // ledger), contribute no span.
        let broken = [block(1, 0, 0.0), block(2, 100, 0.0)];
        assert_eq!(luck_percent(&broken), (None, 0));
        let reset = [block(1, 500, 100.0), block(2, 100, 100.0)];
        assert_eq!(luck_percent(&reset), (None, 0));
    }

    #[test]
    fn history_keeps_the_newest_cap_samples() {
        let mut h = VecDeque::new();
        for i in 0..(HISTORY_CAP as u64 + 5) {
            push_sample(&mut h, i, 1.0);
        }
        assert_eq!(h.len(), HISTORY_CAP);
        assert_eq!(h.front().copied(), Some((5, 1.0)), "the oldest five were discarded");
    }
}
