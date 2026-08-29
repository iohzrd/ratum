//! A read-only HTTP interface: a JSON snapshot of the pool's state at `/stats.json` and a
//! single page at `/` that fetches and renders it. It reads the same `Arc<Server>` the
//! connection threads share, takes no action, and serves only GET, so it adds no way to
//! change the pool. It is started only when `--stats-listen` names an address; bind it to
//! `127.0.0.1` unless it is behind a reverse proxy, since the page is unauthenticated.

use crate::server::{Resolver, Server, unix_now};
use log::warn;
use ratum::datum::messages::MAX_COINBASER_OUTPUTS;
use ratum::http;
use ratum::lock;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, LazyLock};
use tiny_http::{Method, Request, Server as HttpServer};

static INDEX_HTML: LazyLock<String> =
    LazyLock::new(|| ratum::web::assemble(include_str!("stats.html")));

/// Bind `listen` and serve the stats interface on a thread. Returns the bound address (so a
/// `:0` port resolves to the real one) or an error if the address cannot be bound, which the
/// caller reports; the pool keeps running either way.
pub(crate) fn spawn(server: Arc<Server>, listen: &str) -> Result<SocketAddr, String> {
    let http = HttpServer::http(listen).map_err(|e| e.to_string())?;
    let addr = http.server_addr().to_ip().ok_or("no socket address")?;
    http::serve("stats", http, move |request| {
        if let Err(e) = handle(&server, request) {
            warn!("stats: could not send a response: {e}");
        }
    });
    Ok(addr)
}

fn handle(server: &Server, request: Request) -> std::io::Result<()> {
    if *request.method() != Method::Get {
        return request.respond(http::method_not_allowed());
    }
    // The paths carry no parameters.
    let (path, _) = http::path_and_query(&request);
    match path.as_str() {
        "/" | "/index.html" => request.respond(http::html(INDEX_HTML.clone())),
        "/stats.json" => request.respond(http::body(snapshot(server), "application/json")),
        _ => request.respond(http::not_found()),
    }
}

/// The JSON snapshot. Every field is read from the shared state; no secret (the node
/// credentials, the pool signing key) is included. `work` values are `u128`, which JSON
/// numbers cannot hold in full, so they are strings.
fn snapshot(server: &Server) -> String {
    let tip = *lock(&server.tip);
    let coinbase_value = *lock(&server.coinbase_value);
    let operator_fee = coinbase_value.map_or(0, |v| server.payout.fee_on(v));
    let miners_share = coinbase_value.unwrap_or(0).saturating_sub(operator_fee);

    let (total_work, target_work, shares, work_by_identity, split) = {
        let l = lock(&server.ledger);
        (
            l.total_work(),
            l.window(),
            l.len(),
            l.work_by_identity(),
            l.split(miners_share, server.payout.min_payout, MAX_COINBASER_OUTPUTS),
        )
    };
    let payout_sats: HashMap<String, u64> = split.into_iter().collect();

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
        "window": {
            "work": total_work.to_string(),
            "target_work": target_work.to_string(),
            "shares": shares,
            "operator_fee_sats": operator_fee,
            "miners": miners,
        },
        "generated_at": unix_now(),
    });
    snapshot.to_string()
}
