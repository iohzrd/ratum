//! The JSON the status page and the miner lookup render from: one snapshot of the gateway's state
//! per request.

use super::Context;
use crate::config::Config;
use crate::job::Job;
use crate::stratum::ClientStats;
use crate::tally::ShareTallies;
use crate::username;
use ratum::bitcoin::address;
use ratum::lock;
use serde_json::{Value, json};
use std::sync::atomic::Ordering;

fn seconds_ago(t: Option<std::time::Instant>) -> f64 {
    t.map_or(-1.0, |t| t.elapsed().as_secs_f64())
}

/// A rate in hashes per second as the `hashrate_ths` fields carry it: terahashes per second.
fn ths(hashes_per_second: f64) -> f64 {
    hashes_per_second / ratum::HASHES_PER_TERAHASH
}

fn or_null(text: &str) -> Value {
    if text.is_empty() { Value::Null } else { json!(text) }
}

fn pool_host_json(cfg: &Config) -> Value {
    if cfg.datum.pool_host.is_empty() {
        Value::Null
    } else {
        json!(format!("{}:{}", cfg.datum.pool_host, cfg.datum.pool_port))
    }
}

fn client_json(c: &ClientStats) -> Value {
    json!({
        "last_accepted_seconds": seconds_ago(c.last_accepted_at),
        "vardiff": c.current_diff,
        "accepted_diff": c.shares.accepted.diff,
        "accepted_count": c.shares.accepted.count,
        "rejected_diff": c.shares.rejected.diff,
        "rejected_count": c.shares.rejected.count,
        "hashrate_ths": c.hashrate_hs().map(ths),
    })
}

fn admin_client_json(cfg: &Config, unique_id: u64, c: &ClientStats) -> Value {
    let unpayable = cfg.stratum.refuses_username(&c.username);
    super::with_fields(
        client_json(c),
        [
            ("subscribed_seconds", json!(seconds_ago(c.subscribed_at))),
            ("id", json!(unique_id)),
            ("remote", json!(c.peer)),
            ("username", json!(c.username)),
            ("unpayable", json!(unpayable)),
            ("useragent", json!(c.user_agent)),
            ("subscribed", json!(c.subscribed())),
        ],
    )
}

fn miner_client_json(c: &ClientStats) -> Value {
    super::with_fields(client_json(c), [("connected_seconds", json!(seconds_ago(c.subscribed_at)))])
}

fn job_json(j: &Job) -> Value {
    json!({
        "job_id": j.stratum_job_id,
        "slot": j.slot,
        "created_seconds_ago": j.created_at.elapsed().as_secs_f64(),
        "height": j.template.height,
        "value_btc": ratum::sats_to_btc(j.template.coinbase_value),
        "previous_block": ratum::bitcoin::hash_to_display_hex(&j.template.prev_hash),
        "target": hex::encode(j.block_target),
        "witness_commitment": hex::encode(&j.template.witness_commitment),
        "difficulty": ratum::target::difficulty_from_bits(j.template.nbits),
        "version": format!("{:08x}", j.template.version),
        "bits": format!("{:08x}", j.template.nbits),
        "curtime": j.template.curtime,
        "mintime": j.template.mintime,
        "sizelimit": j.template.sizelimit,
        "weightlimit": j.template.weightlimit,
        "sigoplimit": j.template.sigoplimit,
        "txn_count": j.template.txns.len(),
        "txn_total_size": j.template.totals.size,
        "txn_total_weight": j.template.totals.weight,
        "txn_total_sigops": j.template.totals.sigops,
        "is_datum_job": j.is_datum_job,
        "coinbaser_outputs": j.coinbaser_outputs.len(),
    })
}

/// The split's outputs and, when they leave any value, the remainder the pool script receives.
fn coinbaser_json(j: &Job) -> Vec<Value> {
    let row = |value: u64, script: &[u8], remainder: bool| {
        json!({
            "value_btc": ratum::sats_to_btc(value),
            "address": address::output_script_to_display(script),
            "remainder": remainder,
        })
    };
    let mut rows: Vec<Value> =
        j.coinbaser_outputs.iter().map(|o| row(o.value, &o.script_pubkey, false)).collect();
    let paid: u64 = j.coinbaser_outputs.iter().map(|o| o.value).sum();
    if paid < j.template.coinbase_value {
        rows.push(row(j.template.coinbase_value - paid, &j.pool_payout_script, true));
    }
    rows
}

pub(super) fn status_json(ctx: &Context, with_clients: bool) -> Value {
    let gateway = &ctx.gateway;
    let cfg = &gateway.config;
    let pool_tallies = gateway.pool.tallies();
    let pool = gateway.pool.pool_config();
    let work_error = gateway.work_error.get();
    let current = gateway.jobs.current();
    // `state` is what the status page switches on and `status` is the sentence it displays,
    // so rewording the sentence does not change the page's colour or its banner.
    let (state, status) = if let Some(e) = &work_error {
        ("error", format!("ERROR: {e}"))
    } else if cfg.datum.pool_host.is_empty() {
        ("non_pooled", "Non-Pooled Mode".to_string())
    } else if current.is_none() {
        ("initialising", "Initialising...".to_string())
    } else if gateway.pool.is_active() {
        ("ready", "Connected and Ready".to_string())
    } else if cfg.datum.pooled_mining_only {
        ("not_ready", "Not Ready".to_string())
    } else {
        ("non_pooled_unreachable", "Non-Pooled Mode (pool unreachable)".to_string())
    };
    let job = current.as_ref().map(|p| job_json(&p.job));
    let coinbaser = current.as_ref().map(|p| coinbaser_json(&p.job));
    let clients = with_clients.then(|| {
        gateway
            .stratum
            .client_stats()
            .iter()
            .map(|(id, c)| admin_client_json(cfg, *id, c))
            .collect::<Vec<_>>()
    });
    let summary = gateway.stratum.summary();
    json!({
        "version": crate::VERSION,
        "state": state,
        "status": status,
        "uptime_seconds": ctx.started_at.elapsed().as_secs(),
        "work_update_seconds": cfg.bitcoind.work_update_seconds,
        "stale_window_seconds": cfg.stale_window().as_secs(),
        "hashrate": {
            "interval_seconds": ratum::hashrate::INTERVAL_SECS,
            "history": lock(&ctx.hashrate_history).json(),
        },
        "shares_accepted": pool_tallies.accepted.json(),
        "shares_rejected": pool_tallies.rejected.json(),
        "pool_host": pool_host_json(cfg),
        "pool_url": or_null(&cfg.datum.pool_url),
        "pool_pubkey": cfg.datum.pool_pubkey,
        "pool_tag": pool.as_ref().map_or_else(|| cfg.mining.coinbase_tag_primary.clone(), |p| p.coinbase_tag.clone()),
        "secondary_tag": cfg.mining.coinbase_tag_secondary,
        "pool_min_diff": pool.as_ref().map(|p| p.min_difficulty),
        "pool_motd": gateway.pool.motd(),
        "stratum": {
            "listening": gateway.stratum.listening.load(Ordering::Relaxed),
            "connections": summary.connections,
            "subscriptions": summary.subscribed,
            "hashrate_ths": ths(summary.hashrate_hs),
            "network_hashps": gateway.mining_info.network_hashps(),
            "network_share": gateway.mining_info.network_share(summary.hashrate_hs),
            "max_network_share": cfg.max_network_share(),
        },
        "node_warnings": gateway.mining_info.warnings(),
        "job": job,
        "coinbaser": coinbaser,
        "clients": clients,
        "csrf": if with_clients { json!(ctx.csrf_token) } else { Value::Null },
    })
}

#[derive(Default)]
struct MinerTotals {
    shares: ShareTallies,
    hashrate_hs: f64,
}

impl MinerTotals {
    fn add(&mut self, c: &ClientStats) {
        self.shares.accepted.merge(&c.shares.accepted);
        self.shares.rejected.merge(&c.shares.rejected);
        self.hashrate_hs += c.hashrate_hs().unwrap_or(0.0);
    }
}

pub(super) fn miner_lookup_json(ctx: &Context, addr: Option<&str>) -> Value {
    let cfg = &ctx.gateway.config;
    let valid = addr.filter(|a| address::is_valid(a, None));
    let modifiers = &cfg.stratum.username_modifiers;
    let clients = valid.map_or_else(Vec::new, |a| {
        ctx.gateway.stratum.client_stats_where(|c| {
            c.subscribed() && username::address_of(&c.username, modifiers) == a
        })
    });
    let mut totals = MinerTotals::default();
    let connections: Vec<Value> = clients
        .iter()
        .map(|(_, c)| {
            totals.add(c);
            miner_client_json(c)
        })
        .collect();
    json!({
        "address": valid,
        "connection_count": connections.len(),
        "connections": connections,
        "accepted_diff": totals.shares.accepted.diff,
        "accepted_count": totals.shares.accepted.count,
        "rejected_diff": totals.shares.rejected.diff,
        "rejected_count": totals.shares.rejected.count,
        "hashrate_ths": ths(totals.hashrate_hs),
        "stratum_port": cfg.stratum.listen_port,
        "require_address_username": cfg.stratum.require_address_username,
        "max_network_share_bps": cfg.stratum.max_network_share_bps,
        "network_share": ctx.gateway.network_share(),
        "pool_host": pool_host_json(cfg),
        "pool_url": or_null(&cfg.datum.pool_url),
    })
}
