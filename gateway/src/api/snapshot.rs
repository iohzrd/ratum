use super::Context;
use crate::config::Config;
use crate::job::Job;
use crate::stratum::ClientStats;
use crate::tally::Tally;
use crate::{address, username};
use serde_json::{Value, json};
use std::sync::atomic::Ordering;

fn duration_text(d: std::time::Duration) -> String {
    use ratum::{SECS_PER_DAY, SECS_PER_HOUR, SECS_PER_MINUTE};
    let s = d.as_secs();
    format!(
        "{} days, {} hours, {} minutes, {} seconds",
        s / SECS_PER_DAY,
        (s % SECS_PER_DAY) / SECS_PER_HOUR,
        (s % SECS_PER_HOUR) / SECS_PER_MINUTE,
        s % SECS_PER_MINUTE
    )
}

fn seconds_ago(t: Option<std::time::Instant>) -> f64 {
    t.map_or(-1.0, |t| t.elapsed().as_secs_f64())
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
        "last_accepted_seconds": seconds_ago(c.last_accepted),
        "vardiff": c.current_diff,
        "accepted_diff": c.accepted.diff,
        "accepted_count": c.accepted.count,
        "rejected_diff": c.rejected.diff,
        "rejected_count": c.rejected.count,
        "fee_diff": c.fee.diff,
        "fee_count": c.fee.count,
        "hashrate_ths": c.hashrate_ths(),
    })
}

fn admin_client_json(cfg: &Config, c: &ClientStats) -> Value {
    let unpayable = cfg.stratum.require_address_username && !username::is_payable(&c.username);
    super::with_fields(
        client_json(c),
        [
            ("subscribed_seconds", json!(seconds_ago(c.subscribed_at))),
            ("id", json!(c.unique_id)),
            ("remote", json!(c.remote)),
            ("username", json!(c.username)),
            ("unpayable", json!(unpayable)),
            ("useragent", json!(c.useragent)),
            ("subscribed", json!(c.subscribed)),
        ],
    )
}

fn miner_client_json(c: &ClientStats) -> Value {
    super::with_fields(client_json(c), [("connected_seconds", json!(seconds_ago(c.subscribed_at)))])
}

fn job_json(j: &Job) -> Value {
    json!({
        "job_id": j.job_id,
        "global_index": j.global_index,
        "created_seconds_ago": j.created.elapsed().as_secs_f64(),
        "height": j.template.height,
        "value_btc": j.template.coinbase_value as f64 / ratum::SATS_PER_BTC,
        "previous_block": j.template.prev_hash_hex,
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

fn coinbaser_json(j: &Job) -> Vec<Value> {
    j.payout_rows()
        .iter()
        .map(|r| {
            json!({
                "value_btc": r.value as f64 / ratum::SATS_PER_BTC,
                "address": address::output_script_to_display(&r.script),
                "remainder": r.remainder,
            })
        })
        .collect()
}

pub(super) fn status_json(ctx: &Context, with_clients: bool) -> Value {
    let server = &ctx.server;
    let cfg = &server.config;
    let datum_stats = ratum::lock(&server.datum.stats).clone();
    let pool = server.datum.pool_config();
    let template_error = ratum::lock(&ctx.template_error).clone();
    let current = server.current_job();
    let status = if let Some(e) = &template_error {
        format!("ERROR: {e}")
    } else if cfg.datum.pool_host.is_empty() {
        "Non-Pooled Mode".to_string()
    } else if current.is_none() {
        "Initialising...".to_string()
    } else if server.datum.is_active() {
        "Connected and Ready".to_string()
    } else if cfg.datum.pooled_mining_only {
        "Not Ready".to_string()
    } else {
        "Non-Pooled Mode (pool unreachable)".to_string()
    };
    let job = current.as_deref().map(job_json);
    let coinbaser = current.as_deref().map(coinbaser_json);
    let clients = with_clients.then(|| {
        server.client_stats().iter().map(|c| admin_client_json(cfg, c)).collect::<Vec<_>>()
    });
    let summary = server.summary();
    json!({
        "version": ratum::VERSION,
        "status": status,
        "uptime": duration_text(ctx.started.elapsed()),
        "uptime_seconds": ctx.started.elapsed().as_secs(),
        "work_update_seconds": cfg.bitcoind.work_update_seconds,
        "stale_window_seconds": cfg.stale_window().as_secs(),
        "hashrate": {
            "interval_seconds": ratum::hashrate::INTERVAL_SECS,
            "history": ratum::lock(&ctx.history)
                .iter()
                .map(|(at, hs)| json!([at, hs.round()]))
                .collect::<Vec<_>>(),
        },
        "shares_accepted": datum_stats.accepted.json(),
        "shares_rejected": datum_stats.rejected.json(),
        "pool_host": pool_host_json(cfg),
        "pool_url": or_null(&cfg.datum.pool_url),
        "pool_pubkey": cfg.datum.pool_pubkey,
        "pool_tag": pool.as_ref().map_or_else(|| cfg.mining.coinbase_tag_primary.clone(), |p| p.coinbase_tag.clone()),
        "secondary_tag": cfg.mining.coinbase_tag_secondary,
        "pool_min_diff": pool.as_ref().map(|p| p.min_difficulty),
        "pool_motd": datum_stats.motd,
        "gateway_fee_bps": cfg.datum.gateway_fee_bps,
        "gateway_fee_address": if cfg.datum.gateway_fee_bps > 0 { json!(cfg.fee_address()) } else { Value::Null },
        "gateway_fee_collected": ratum::lock(&server.fee).json(),
        "stratum": {
            "listening": server.listening.load(Ordering::Relaxed),
            "connections": summary.connections,
            "subscriptions": summary.subscribed,
            "hashrate_ths": summary.hashrate_ths,
        },
        "job": job,
        "coinbaser": coinbaser,
        "clients": clients,
        "csrf": if with_clients { json!(ctx.csrf) } else { Value::Null },
    })
}

#[derive(Default)]
struct MinerTotals {
    accepted: Tally,
    rejected: Tally,
    fee: Tally,
    hashrate_ths: f64,
}

impl MinerTotals {
    fn add(&mut self, c: &ClientStats) {
        self.accepted.merge(&c.accepted);
        self.rejected.merge(&c.rejected);
        self.fee.merge(&c.fee);
        self.hashrate_ths += c.hashrate_ths().unwrap_or(0.0);
    }
}

pub(super) fn miner_lookup_json(ctx: &Context, addr: Option<&str>) -> Value {
    let cfg = &ctx.server.config;
    let valid = addr.filter(|a| address::is_valid(a));
    let clients = valid.map_or_else(Vec::new, |a| {
        ctx.server.client_stats_where(|c| c.subscribed && username::address_of(&c.username) == a)
    });
    let mut totals = MinerTotals::default();
    let connections: Vec<Value> = clients
        .iter()
        .map(|c| {
            totals.add(c);
            miner_client_json(c)
        })
        .collect();
    json!({
        "address": valid,
        "fee_bps": cfg.datum.gateway_fee_bps,
        "fee_address": if cfg.datum.gateway_fee_bps > 0 { cfg.fee_address() } else { "" },
        "connection_count": connections.len(),
        "connections": connections,
        "accepted_diff": totals.accepted.diff,
        "accepted_count": totals.accepted.count,
        "rejected_diff": totals.rejected.diff,
        "rejected_count": totals.rejected.count,
        "fee_diff": totals.fee.diff,
        "fee_count": totals.fee.count,
        "accepted_under_address_diff": totals.accepted.diff.saturating_sub(totals.fee.diff),
        "hashrate_ths": totals.hashrate_ths,
        "stratum_port": cfg.stratum.listen_port,
        "require_address_username": cfg.stratum.require_address_username,
        "pool_host": pool_host_json(cfg),
        "pool_url": or_null(&cfg.datum.pool_url),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uptime_text() {
        assert_eq!(
            duration_text(std::time::Duration::from_secs(90061)),
            "1 days, 1 hours, 1 minutes, 1 seconds"
        );
    }
}
