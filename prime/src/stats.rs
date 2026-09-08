//! A read-only HTTP interface: a JSON snapshot of the pool's state at `/stats.json`, a
//! single page at `/` that renders it, and `/robots.txt`. The page is served with that
//! snapshot embedded, so its first paint needs no fetch (it fetches the snapshot every 5 s
//! after that), and with a one-paragraph summary of the same figures inside `<noscript>`
//! for a reader or crawler that runs no script. Its head names the chain and carries the
//! link-preview tags. It reads the same `Arc<Server>` the
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

/// The page with the shared stylesheet and script in place, holding the `<!--head-->`,
/// `<!--summary-->` and `<!--snapshot-->` markers `page` fills per request.
static PAGE_TEMPLATE: LazyLock<String> =
    LazyLock::new(|| ratum::web::assemble(include_str!("stats.html")));

/// What the head's description and the page's own text call this pool. The chain is named
/// with it so a testnet pool's title is not a mainnet pool's.
const DESCRIPTION: &str = "Non-custodial Bitcoin BLAKE2b mining pool on the Bitcoin Knots \
                           hardfork chain: miners run a DATUM gateway, build their own \
                           blocks and are paid from the coinbase.";

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
        "/" | "/index.html" => {
            let origin = request_origin(&request);
            let page = page(&snapshot(server, history), origin.as_deref());
            request.respond(http::html(page))
        }
        // Crawlable, so a search engine that renders the page can fetch what it renders
        // from, but not a search result of its own.
        "/stats.json" => request.respond(http::noindex(http::body(
            snapshot(server, history).to_string(),
            "application/json",
        ))),
        "/robots.txt" => {
            request.respond(http::body(ROBOTS.to_string(), "text/plain; charset=utf-8"))
        }
        _ => request.respond(http::not_found()),
    }
}

/// Crawling is allowed everywhere: `/stats.json` must be fetchable for a crawler that runs
/// the page's script to see anything, and its `X-Robots-Tag` keeps it out of results.
const ROBOTS: &str = "User-agent: *\nAllow: /\n";

/// The scheme and host the request arrived on, for the canonical and Open Graph URLs:
/// the `Host` header, with the scheme a reverse proxy reports in `X-Forwarded-Proto`.
/// Both are values a client sets, so a host outside the characters a host name and port use
/// is discarded rather than written into the page.
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

/// Whether a `Host` header holds only what a host name, an IPv6 literal and a port are
/// written with, and so can be written into the page.
fn usable_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 255
        && host.chars().all(|c| c.is_ascii_alphanumeric() || "-.:[]".contains(c))
}

/// The page for one request: the head tags, a summary for a reader whose browser runs no
/// script, and the snapshot the page renders its first paint from rather than waiting for
/// its first fetch (which is also what a crawler that renders the page reads).
fn page(snapshot: &serde_json::Value, origin: Option<&str>) -> String {
    let chain = snapshot["network"]["chain"].as_str();
    PAGE_TEMPLATE
        .replace("<!--head-->", &head(chain, origin))
        .replace("<!--summary-->", &summary(snapshot))
        // `</` inside a `<script>` element would end it, and the snapshot carries text a
        // miner chose (its coinbase tag); `<\/` is the same string to a JSON reader.
        .replace("<!--snapshot-->", &snapshot.to_string().replace("</", "<\\/"))
}

/// The title, description, link preview tags and icon. The title leads with what the pool
/// mines because that is what a search for it names; the chain follows when it is not
/// mainnet, so a test pool is not taken for a mainnet one.
fn head(chain: Option<&str>, origin: Option<&str>) -> String {
    let network = match chain {
        Some(c) if c != "main" && !c.is_empty() => format!(" {c}"),
        _ => String::new(),
    };
    let title = attr(&format!("Bitcoin BLAKE2b{network} mining pool - RATUM Prime"));
    let description = attr(DESCRIPTION);
    // An icon drawn in the page's accent color rather than a file to request; a search
    // result shows it beside the title.
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

/// What the page says when its script does not run: the figures every other element on it
/// is drawn from, in one sentence.
fn summary(snapshot: &serde_json::Value) -> String {
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

/// A hashes-per-second figure with a unit that keeps it to a few digits, as the page's own
/// `hashrate` in `page.js` formats it.
fn hashrate_text(hs: f64) -> String {
    const UNITS: [&str; 7] = ["H/s", "kH/s", "MH/s", "GH/s", "TH/s", "PH/s", "EH/s"];
    let mut hs = hs;
    let mut i = 0;
    while hs >= 1000.0 && i < UNITS.len() - 1 {
        hs /= 1000.0;
        i += 1;
    }
    format!("{hs:.1} {}", UNITS[i])
}

/// Text written into an HTML attribute or element.
fn attr(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// The JSON snapshot. Every field is read from the shared state; no secret (the node
/// credentials, the pool signing key) is included. `work` values are `u128`, which JSON
/// numbers cannot hold in full, so they are strings.
fn snapshot(server: &Server, history: &Mutex<VecDeque<(u64, f64)>>) -> serde_json::Value {
    let tip = *lock(&server.node_view.tip);
    let coinbase_value = *lock(&server.node_view.coinbase_value);
    let operator_fee = coinbase_value.map_or(0, |v| server.payout.fee_on(v));

    let hashrate_cutoff = unix_now().saturating_sub(HASHRATE_SPAN_SECS);
    let (total_work, target_work, shares, work_by_identity, tags, split, owed, recent, blocks) = {
        let l = lock(&server.ledger);
        (
            l.total_work(),
            l.window(),
            l.len(),
            l.work_by_identity(),
            l.tags_by_identity(),
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
                "tag": b.tag,
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

    // What the pool's payout script received on each block that the window is owed (outputs
    // the coinbase left out, or a coinbase that paid the window nothing), per block and
    // summed per identity while unsettled. Settlement is a wallet transaction the operator
    // records with --settle-block.
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
                // The gateway tag the identity's newest share in the window came through.
                "tag": tags.get(identity).map_or("", String::as_str),
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

    serde_json::json!({
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
            // A gateway open to miners who do not run their own, or null.
            "public_gateway": server.public_gateway,
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn demo_snapshot(tag: &str) -> serde_json::Value {
        serde_json::json!({
            "pool": { "coinbase_tag": tag },
            "network": { "chain": "testnet4", "tip_height": 150_308 },
            "hashrate": { "pool_hs": 12_500_000_000_000.0f64 },
            "window": { "miners": [{ "identity": "alice" }, { "identity": "bob" }] },
            "blocks": { "found": 3 },
        })
    }

    /// The embedded snapshot carries text a miner chose, so a `</script>` in it would end
    /// the element and put the rest of the snapshot into the page as markup.
    #[test]
    fn an_embedded_snapshot_cannot_end_the_script_element() {
        let page = page(&demo_snapshot("</script><img src=x>"), None);
        assert!(page.contains(r"<\/script><img src=x>"), "the sequence is escaped");
        assert!(!page.contains("</script><img src=x>"), "and not written as it stands");
        // The escape is a JSON one, so the tag reads back as the miner wrote it.
        let embedded = page
            .split_once("<script id=\"snapshot\" type=\"application/json\">")
            .and_then(|(_, rest)| rest.split_once("</script>"))
            .expect("the snapshot element");
        let read: serde_json::Value = serde_json::from_str(embedded.0).expect("valid json");
        assert_eq!(read["pool"]["coinbase_tag"], "</script><img src=x>");
    }

    /// The title leads with what the pool mines and names the chain when it is not mainnet.
    #[test]
    fn the_title_and_description_name_the_chain_and_the_fork() {
        let page = page(&demo_snapshot(""), None);
        assert!(
            page.contains("<title>Bitcoin BLAKE2b testnet4 mining pool - RATUM Prime</title>"),
            "{}",
            &page[..400]
        );
        assert!(
            page.contains("<meta name=\"description\" content=\"Non-custodial Bitcoin BLAKE2b")
        );
        assert!(page.contains("<meta property=\"og:title\""), "a link preview reads the OG tags");
        // The figures, for a reader whose browser runs no script.
        assert!(page.contains("at height 150308"));
        assert!(page.contains("12.5 TH/s across 2 miners"));
        assert!(page.contains("with 3 blocks found"));
    }

    /// A mainnet pool's title carries no chain name, and the canonical URL is written only
    /// when the request named a host that can be written into the page.
    #[test]
    fn mainnet_has_no_chain_in_its_title_and_the_canonical_url_follows_the_host() {
        let mut snapshot = demo_snapshot("");
        snapshot["network"]["chain"] = serde_json::json!("main");
        let page = page(&snapshot, Some("https://pool.example"));
        assert!(page.contains("<title>Bitcoin BLAKE2b mining pool - RATUM Prime</title>"));
        assert!(page.contains("<link rel=\"canonical\" href=\"https://pool.example/\">"));
        assert!(!super::page(&snapshot, None).contains("rel=\"canonical\""));
    }

    #[test]
    fn a_host_header_outside_what_a_host_is_written_with_is_not_used() {
        assert!(usable_host("pool.iohzrd.tech"));
        assert!(usable_host("127.0.0.1:38080"));
        assert!(usable_host("[::1]:38080"));
        assert!(!usable_host(""));
        assert!(!usable_host("pool.example\" onload=alert(1) x=\""));
        assert!(!usable_host(&"a".repeat(256)));
    }

    fn block(n: u8, cumulative_work: u128, difficulty: f64) -> FoundBlock {
        FoundBlock {
            at: u64::from(n),
            height: u32::from(n),
            block_hash: [n; 32],
            paid_to_split: 0,
            paid_to_pool: 0,
            finder: "a".into(),
            tag: String::new(),
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
