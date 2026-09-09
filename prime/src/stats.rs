use crate::server::{Resolver, Server, split_after_fee};
use log::warn;
use ratum::http;
use ratum::lock;
use ratum_prime::ledger::{self, FoundBlock};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, LazyLock, Mutex};
use tiny_http::{Method, Request, Server as HttpServer};

static PAGE_TEMPLATE: LazyLock<String> =
    LazyLock::new(|| ratum::web::assemble(include_str!("stats.html")));

const DESCRIPTION: &str = "Non-custodial Bitcoin BLAKE2b mining pool on the Bitcoin Knots \
                           hardfork chain: miners run a DATUM gateway, build their own \
                           blocks and are paid from the coinbase.";

const HASHRATE_SPAN_SECS: u64 = 10 * ratum::SECS_PER_MINUTE;

fn hashes_per_second(work: u128, secs: u64) -> f64 {
    if secs == 0 {
        return 0.0;
    }
    work as f64 * ratum::HASHES_PER_DIFFICULTY / secs as f64
}

const TARGET_BLOCK_SECS: f64 = 10.0 * ratum::SECS_PER_MINUTE as f64;
const RETARGET_TIMESPAN_SECS: f64 = 14.0 * ratum::SECS_PER_DAY as f64;
const RETARGET_INTERVAL: u32 = (RETARGET_TIMESPAN_SECS / TARGET_BLOCK_SECS) as u32;
const MAX_RETARGET_FACTOR: f64 = 4.0;

const RECENT_BLOCKS: usize = 50;

type HashrateHistory = Arc<Mutex<ratum::web::History>>;

fn sample_hashrate(server: &Server, history: &Mutex<ratum::web::History>) {
    let now = ratum::unix_now();
    let (work, _) = lock(&server.ledger).work_since(now.saturating_sub(HASHRATE_SPAN_SECS));
    ratum::web::push_sample(&mut lock(history), now, hashes_per_second(work, HASHRATE_SPAN_SECS));
}

fn luck_percent(blocks: &[FoundBlock]) -> (Option<f64>, u32) {
    let mut expected = 0.0f64;
    let mut counted = 0u32;
    for pair in blocks.windows(2) {
        let (prev, b) = (&pair[0], &pair[1]);
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

pub(crate) fn spawn(server: Arc<Server>, listen: &str) -> Result<SocketAddr, String> {
    let http = HttpServer::http(listen).map_err(|e| e.to_string())?;
    let addr = http.server_addr().to_ip().ok_or("no socket address")?;
    let history: HashrateHistory = Arc::new(Mutex::new(ratum::web::History::new()));
    let (sampler, sampler_history) = (Arc::clone(&server), Arc::clone(&history));
    ratum::web::sample_periodically("stats-sampler", move || {
        sample_hashrate(&sampler, &sampler_history);
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
    history: &Mutex<ratum::web::History>,
    request: Request,
) -> std::io::Result<()> {
    if *request.method() != Method::Get {
        return request.respond(http::method_not_allowed());
    }
    let (path, _) = http::path_and_query(&request);
    match path.as_str() {
        "/" | "/index.html" => {
            let origin = request_origin(&request);
            let page = page(&snapshot(server, history), origin.as_deref());
            request.respond(http::html(page))
        }
        "/stats.json" => request.respond(http::noindex(http::json(snapshot(server, history)))),
        "/robots.txt" => request.respond(http::plain(ROBOTS.to_string())),
        _ => request.respond(http::not_found()),
    }
}

const ROBOTS: &str = "User-agent: *\nAllow: /\n";

fn request_origin(request: &Request) -> Option<String> {
    let host = http::header_value(request, "Host")?;
    if !usable_host(&host) {
        return None;
    }
    let proto = match http::header_value(request, "X-Forwarded-Proto").as_deref() {
        Some("https") => "https",
        _ => "http",
    };
    Some(format!("{proto}://{host}"))
}

const MAX_HOST_CHARS: usize = 255;

fn usable_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= MAX_HOST_CHARS
        && host.chars().all(|c| c.is_ascii_alphanumeric() || "-.:[]".contains(c))
}

fn page(snapshot: &Value, origin: Option<&str>) -> String {
    let chain = snapshot["network"]["chain"].as_str();
    PAGE_TEMPLATE
        .replace("<!--head-->", &head(chain, origin))
        .replace("<!--summary-->", &summary(snapshot))
        .replace("<!--snapshot-->", &snapshot.to_string().replace("</", "<\\/"))
}

fn head(chain: Option<&str>, origin: Option<&str>) -> String {
    let network = match chain {
        Some(c) if c != "main" && !c.is_empty() => format!(" {c}"),
        _ => String::new(),
    };
    let title = attr(&format!("Bitcoin BLAKE2b{network} mining pool - RATUM Prime"));
    let description = attr(DESCRIPTION);
    let icon = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'\
                %3E%3Crect width='16' height='16' rx='3' fill='%230f1115'/%3E%3Ctext x='8' \
                y='12' font-size='11' font-family='monospace' font-weight='bold' \
                text-anchor='middle' fill='%236ea8fe'%3ER%3C/text%3E%3C/svg%3E";
    let canonical = origin.map_or(String::new(), |o| {
        let url = attr(&format!("{o}/"));
        format!(
            "<link rel=\"canonical\" href=\"{url}\">\n<meta property=\"og:url\" content=\"{url}\">\n"
        )
    });
    format!(
        "<title>{title}</title>\n\
         <meta name=\"description\" content=\"{description}\">\n\
         <link rel=\"icon\" href=\"{icon}\">\n\
         {canonical}\
         <meta property=\"og:type\" content=\"website\">\n\
         <meta property=\"og:site_name\" content=\"RATUM Prime\">\n\
         <meta property=\"og:title\" content=\"{title}\">\n\
         <meta property=\"og:description\" content=\"{description}\">\n\
         <meta name=\"twitter:card\" content=\"summary\">\n"
    )
}

fn summary(snapshot: &Value) -> String {
    let chain = snapshot["network"]["chain"].as_str().unwrap_or("");
    let height = snapshot["network"]["tip_height"].as_u64();
    let rate = snapshot["hashrate"]["pool_hs"].as_f64().unwrap_or(0.0);
    let miners = snapshot["window"]["miners"].as_array().map_or(0, Vec::len);
    let found = snapshot["blocks"]["found"].as_u64().unwrap_or(0);
    let at = match (chain.is_empty(), height) {
        (false, Some(h)) => format!(" on {} at height {h}", attr(chain)),
        (false, None) => format!(" on {}", attr(chain)),
        (true, _) => String::new(),
    };
    format!(
        "{DESCRIPTION} It is mining{at}, at about {} across {miners} miners in the payout \
         window, with {found} blocks found. The figures on this page are updated by a \
         script, which is not running.",
        hashrate_text(rate)
    )
}

fn hashrate_text(hs: f64) -> String {
    const UNITS: [&str; 7] = ["H/s", "kH/s", "MH/s", "GH/s", "TH/s", "PH/s", "EH/s"];
    const SI_STEP: f64 = 1000.0;
    let mut hs = hs;
    let mut i = 0;
    while hs >= SI_STEP && i < UNITS.len() - 1 {
        hs /= SI_STEP;
        i += 1;
    }
    format!("{hs:.1} {}", UNITS[i])
}

fn attr(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
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
        "tip_hash": hex::encode(ratum::bitcoin::reversed(&t.hash)),
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

fn owed_json(owed: &[ledger::OwedBlock]) -> (u64, Vec<Value>, Vec<Value>) {
    let mut unsettled: u64 = 0;
    let mut by_identity: HashMap<String, u64> = HashMap::new();
    let blocks: Vec<Value> = owed
        .iter()
        .map(|o| {
            if o.settled_at.is_none() {
                unsettled += o.total;
                for (identity, sats) in &o.entries {
                    *by_identity.entry(identity.clone()).or_insert(0) += sats;
                }
            }
            json!({
                "height": o.height,
                "block_hash": hex::encode(o.block_hash),
                "found_at": o.at,
                "total_sats": o.total,
                "settled_at": o.settled_at,
                "miners": o.entries.iter().map(|(identity, sats)| {
                    json!({ "identity": identity, "sats": sats })
                }).collect::<Vec<_>>(),
            })
        })
        .collect();
    let mut by_identity: Vec<(String, u64)> = by_identity.into_iter().collect();
    by_identity.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let by_identity = by_identity
        .into_iter()
        .map(|(identity, sats)| json!({ "identity": identity, "sats": sats }))
        .collect();
    (unsettled, by_identity, blocks)
}

fn miners_json(
    server: &Server,
    work_by_identity: &[(String, u128)],
    total_work: u128,
    payout_sats: &HashMap<String, u64>,
    recent_by_identity: &HashMap<String, u128>,
    tags: &HashMap<String, String>,
) -> Vec<Value> {
    work_by_identity
        .iter()
        .map(|(identity, work)| {
            let share_percent =
                if total_work > 0 { *work as f64 / total_work as f64 * 100.0 } else { 0.0 };
            let (payable, unpayable_reason) = match Resolver::cached(&server.resolver, identity) {
                Some(Ok(_)) => (Some(true), None),
                Some(Err(why)) => (Some(false), Some(why.to_string())),
                None => (None, None),
            };
            json!({
                "identity": identity,
                "work": work.to_string(),
                "share_percent": share_percent,
                "hashrate_hs": hashes_per_second(
                    recent_by_identity.get(identity).copied().unwrap_or(0),
                    HASHRATE_SPAN_SECS,
                ),
                "payout_sats": payout_sats.get(identity).copied().unwrap_or(0),
                "payable": payable,
                "unpayable_reason": unpayable_reason,
                "tag": tags.get(identity).map_or("", String::as_str),
            })
        })
        .collect()
}

struct LedgerView {
    total_work: u128,
    target_work: u128,
    shares: usize,
    work_by_identity: Vec<(String, u128)>,
    tags: HashMap<String, String>,
    payout_sats: HashMap<String, u64>,
    owed: Vec<ledger::OwedBlock>,
    blocks: Vec<FoundBlock>,
    recent_work: u128,
    recent_by_identity: HashMap<String, u128>,
}

impl LedgerView {
    fn read(server: &Server, coinbase_value: Option<u64>) -> Self {
        let cutoff = ratum::unix_now().saturating_sub(HASHRATE_SPAN_SECS);
        let l = lock(&server.ledger);
        let (recent_work, recent_by_identity) = l.work_since(cutoff);
        Self {
            total_work: l.total_work(),
            target_work: l.window(),
            shares: l.len(),
            work_by_identity: l.work_by_identity(),
            tags: l.tags_by_identity(),
            payout_sats: split_after_fee(&l, &server.payout, coinbase_value.unwrap_or(0))
                .into_iter()
                .collect(),
            owed: l.owed().to_vec(),
            blocks: l.blocks().to_vec(),
            recent_work,
            recent_by_identity,
        }
    }
}

fn recent_blocks_json(blocks: &[FoundBlock]) -> Vec<Value> {
    blocks
        .iter()
        .rev()
        .take(RECENT_BLOCKS)
        .map(|b| {
            json!({
                "height": b.height,
                "block_hash": hex::encode(b.block_hash),
                "found_at": b.at,
                "paid_to_split": b.paid_to_split,
                "paid_to_pool": b.paid_to_pool,
                "finder": b.finder,
                "tag": b.tag,
            })
        })
        .collect()
}

fn observed_block_seconds(server: &Server) -> Option<f64> {
    let tips = lock(&server.node_view.tip_history);
    match (tips.front(), tips.back()) {
        (Some(&(h0, t0)), Some(&(h1, t1))) if h1 > h0 && t1 > t0 => {
            Some((t1 - t0) as f64 / f64::from(h1 - h0))
        }
        _ => None,
    }
}

fn snapshot(server: &Server, history: &Mutex<ratum::web::History>) -> Value {
    let tip = *lock(&server.node_view.tip);
    let coinbase_value = *lock(&server.node_view.coinbase_value);
    let operator_fee = coinbase_value.map_or(0, |v| server.payout.fee_on(v));
    let l = LedgerView::read(server, coinbase_value);

    let (luck, luck_blocks) = luck_percent(&l.blocks);
    let (owed_unsettled, owed_by_identity, owed_blocks) = owed_json(&l.owed);
    let miners = miners_json(
        server,
        &l.work_by_identity,
        l.total_work,
        &l.payout_sats,
        &l.recent_by_identity,
        &l.tags,
    );
    let network = network_json(tip, coinbase_value, observed_block_seconds(server));

    json!({
        "pool": {
            "motd": server.motd,
            "version": ratum::VERSION,
            "coinbase_tag": server.policy.coinbase_tag,
            "prime_id": server.policy.prime_id,
            "payout_script": hex::encode(&server.policy.payout_script),
            "fee_bps": server.payout.fee_bps,
            "min_payout": server.payout.min_payout,
            "window_multiple": server.payout.window_multiple,
            "min_difficulty": server.policy.min_difficulty,
            "datum_port": server.datum_port,
            "pubkey": server.pool_keys.pubkey_hex(),
            "advertise": server.advertise,
            "public_gateway": server.public_gateway,
        },
        "network": network,
        "connections": {
            "open": server.open_connections.load(Ordering::Relaxed),
            "max": server.max_connections,
        },
        "hashrate": {
            "span_seconds": HASHRATE_SPAN_SECS,
            "pool_hs": hashes_per_second(l.recent_work, HASHRATE_SPAN_SECS),
            "interval_seconds": ratum::web::HISTORY_INTERVAL_SECS,
            "history": lock(history)
                .iter()
                .map(|&(t, hs)| json!([t, hs as u64]))
                .collect::<Vec<_>>(),
        },
        "window": {
            "work": l.total_work.to_string(),
            "target_work": l.target_work.to_string(),
            "shares": l.shares,
            "operator_fee_sats": operator_fee,
            "miners": miners,
        },
        "owed": {
            "unsettled_sats": owed_unsettled,
            "by_identity": owed_by_identity,
            "blocks": owed_blocks,
        },
        "blocks": {
            "found": l.blocks.len(),
            "luck_percent": luck,
            "luck_blocks": luck_blocks,
            "recent": recent_blocks_json(&l.blocks),
        },
        "generated_at": ratum::unix_now(),
    })
}
