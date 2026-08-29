//! The HTTP interfaces: the admin port (`api.listen_port`) serves `status.html` at `/`,
//! which renders `/stats.json` in the browser as the pool's stats page does, plus
//! `/clients`, `/coinbaser`, `/cmd` and `/NOTIFY`; the password-less miner lookup is on
//! `api.miner_listen_port`. `/clients`, `/cmd` and the client rows of `/stats.json` require
//! `api.admin_password` over HTTP Basic authentication when one is set; the status itself is
//! public, as the C gateway's is. Configuration editing (`api.modify_conf`) is not served.

use crate::stratum::Server;
use log::{info, warn};
use serde_json::json;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use tiny_http::{Header, Method, Request, Response};

const INDEX_HTML: &str = include_str!("status.html");
const MINER_HTML: &str = include_str!("miner.html");

pub struct Context {
    pub server: Arc<Server>,
    pub template_status: Arc<Mutex<crate::template::Status>>,
    pub started: std::time::Instant,
    /// A random token every `/cmd` form carries and `/cmd` requires, so a request a
    /// browser replays the admin credentials on from another site does not act (the C
    /// gateway's `api_csrf_token`).
    pub csrf: String,
}

/// A random token for `Context::csrf`.
pub fn csrf_token() -> String {
    let mut b = [0u8; 16];
    dryoc::rng::copy_randombytes(&mut b);
    hex::encode(b)
}

/// Equality in time that depends on the lengths and not on where the strings differ
/// (`datum_secure_strequals`).
fn secure_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut acc = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        acc |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    acc == 0
}

fn html(body: String) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut r = Response::from_string(body);
    r.add_header(Header::from_bytes("Content-Type", "text/html; charset=utf-8").unwrap());
    r.add_header(
        Header::from_bytes("Cache-Control", "no-cache, no-store, must-revalidate").unwrap(),
    );
    r
}

fn json_response(v: serde_json::Value) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut r = Response::from_string(v.to_string());
    r.add_header(Header::from_bytes("Content-Type", "application/json").unwrap());
    r.add_header(
        Header::from_bytes("Cache-Control", "no-cache, no-store, must-revalidate").unwrap(),
    );
    r
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

const PAGE_CSS: &str = ":root{--bg:#0f1115;--card:#181b22;--line:#262b34;--fg:#e6e8ec;--muted:#9aa3b2;--accent:#6ea8fe;--warn:#f0a04b}*{box-sizing:border-box}body{margin:0;padding:1.5rem;background:var(--bg);color:var(--fg);font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}h1{font-size:1.25rem;margin:0 0 1rem}h2{font-size:1rem;color:var(--muted);margin:1.5rem 0 .6rem}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:.45rem .6rem;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600;font-size:.8rem;text-transform:uppercase}p{margin:.4rem 0;color:var(--muted)}a{color:var(--accent)}code{color:var(--accent)}.tag{margin-left:.5rem;padding:.05rem .4rem;border-radius:.25rem;font-size:.75rem;color:var(--warn);border:1px solid var(--warn)}button,input{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:4px;padding:.1rem .5rem;font:inherit}button{cursor:pointer}button:hover{border-color:var(--accent)}form{display:inline}";

fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{}</title><style>{PAGE_CSS}</style></head><body><h1>{}</h1>{body}<p><a href=\"/\">Status</a> · <a href=\"/clients\">Clients</a> · <a href=\"/coinbaser\">Coinbaser</a></p></body></html>",
        escape(title),
        escape(title)
    )
}

fn duration_text(d: std::time::Duration) -> String {
    let s = d.as_secs();
    format!(
        "{} days, {} hours, {} minutes, {} seconds",
        s / 86400,
        (s % 86400) / 3600,
        (s % 3600) / 60,
        s % 60
    )
}

fn authorized(ctx: &Context, req: &Request) -> bool {
    let password = &ctx.server.config.api.admin_password;
    if password.is_empty() {
        return true;
    }
    let Some(h) = req.headers().iter().find(|h| h.field.equiv("Authorization")) else {
        return false;
    };
    let value = h.value.as_str();
    let Some(b64) = value.strip_prefix("Basic ") else { return false };
    use base64::Engine as _;
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) else {
        return false;
    };
    let decoded = String::from_utf8_lossy(&decoded);
    decoded.split_once(':').is_some_and(|(_, p)| secure_eq(p, password))
}

fn forbidden(why: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(why.to_string()).with_status_code(403)
}

fn unauthorized() -> Response<std::io::Cursor<Vec<u8>>> {
    let mut r = Response::from_string("This action requires admin access.").with_status_code(401);
    r.add_header(Header::from_bytes("WWW-Authenticate", "Basic realm=\"DATUM Gateway\"").unwrap());
    r
}

/// One client's row, as `/stats.json` and the miner lookup report it.
fn client_json(cfg: &crate::config::Config, c: &crate::stratum::ClientStats) -> serde_json::Value {
    json!({
        "id": c.unique_id,
        "remote": c.remote,
        "username": c.username,
        "unpayable": cfg.stratum.require_address_username
            && !crate::address::username_is_payable(&c.username),
        "useragent": c.useragent,
        "subscribed": c.subscribed,
        "subscribed_seconds": c.subscribed_at.map_or(-1.0, |t| t.elapsed().as_secs_f64()),
        "last_accepted_seconds": c.last_accepted.map_or(-1.0, |t| t.elapsed().as_secs_f64()),
        "vardiff": c.current_diff,
        "accepted_diff": c.accepted_diff,
        "accepted_count": c.accepted_count,
        "rejected_diff": c.rejected_diff,
        "rejected_count": c.rejected_count,
        "fee_diff": c.fee_diff,
        "fee_count": c.fee_count,
        "hashrate_ths": c.hashrate_ths(),
        "coinbase": crate::coinbase::TYPE_NAMES.get(c.coinbase_selection as usize).unwrap_or(&"?"),
    })
}

/// The status snapshot. `with_clients` adds the per-connection rows, which need the admin
/// password when one is set.
fn status_json(ctx: &Context, with_clients: bool) -> serde_json::Value {
    let server = &ctx.server;
    let cfg = &server.config;
    let datum_stats = ratum::lock(&server.datum.stats).clone();
    let pool = server.datum.pool_config();
    let template_error = ratum::lock(&ctx.template_status).error.clone();
    let status = if let Some(e) = &template_error {
        format!("ERROR: {e}")
    } else if cfg.datum.pool_host.is_empty() {
        "Non-Pooled Mode".to_string()
    } else if server.current_job().is_none() {
        "Initialising...".to_string()
    } else if server.datum.is_active() {
        "Connected and Ready".to_string()
    } else if cfg.datum.pooled_mining_only {
        "Not Ready".to_string()
    } else {
        // A pool is configured but not connected, and pooled_mining_only is off: the
        // gateway serves work that pays mining.pool_address, as the C gateway does.
        "Non-Pooled Mode (pool unreachable)".to_string()
    };
    let job = server.current_job().map(|j| {
        json!({
            "job_id": j.job_id,
            "global_index": j.global_index,
            "created_seconds_ago": j.created.elapsed().as_secs_f64(),
            "height": j.template.height,
            "value_btc": j.template.coinbase_value as f64 / 1e8,
            "previous_block": j.template.prev_hash_hex,
            "target": j.template.target_hex,
            "witness_commitment": hex::encode(&j.template.witness_commitment),
            "difficulty": ratum::target::difficulty_from_bits(j.template.nbits),
            "version": format!("{:08x}", j.template.version),
            "bits": j.template.bits,
            "curtime": j.template.curtime,
            "mintime": j.template.mintime,
            "sizelimit": j.template.sizelimit,
            "weightlimit": j.template.weightlimit,
            "sigoplimit": j.template.sigoplimit,
            "txn_count": j.template.txns.len(),
            "txn_total_size": j.template.txn_total_size,
            "txn_total_weight": j.template.txn_total_weight,
            "txn_total_sigops": j.template.txn_total_sigops,
            "is_datum_job": j.is_datum_job,
            "coinbaser_outputs": j.coinbaser_outputs.len(),
        })
    });
    let coinbaser = server.current_job().map(|j| {
        let mut outs: Vec<serde_json::Value> = j
            .coinbaser_outputs
            .iter()
            .map(|o| {
                json!({
                    "value_btc": o.value as f64 / 1e8,
                    "address": crate::address::output_script_to_display(&o.script),
                    "remainder": false,
                })
            })
            .collect();
        let paid: u64 = j.coinbaser_outputs.iter().map(|o| o.value).sum();
        if paid < j.template.coinbase_value {
            outs.push(json!({
                "value_btc": (j.template.coinbase_value - paid) as f64 / 1e8,
                "address": crate::address::output_script_to_display(&j.pool_addr_script),
                "remainder": true,
            }));
        }
        outs
    });
    let clients = with_clients
        .then(|| server.client_stats().iter().map(|c| client_json(cfg, c)).collect::<Vec<_>>());
    json!({
        "version": crate::VERSION,
        "status": status,
        "uptime": duration_text(ctx.started.elapsed()),
        "shares_accepted": {"count": datum_stats.accepted_count, "diff": datum_stats.accepted_diff},
        "shares_rejected": {"count": datum_stats.rejected_count, "diff": datum_stats.rejected_diff},
        "pool_host": if cfg.datum.pool_host.is_empty() { Value::Null } else { json!(format!("{}:{}", cfg.datum.pool_host, cfg.datum.pool_port)) },
        "pool_pubkey": cfg.datum.pool_pubkey,
        "pool_tag": pool.as_ref().map_or(cfg.mining.coinbase_tag_primary.clone(), |p| p.coinbase_tag.clone()),
        "secondary_tag": cfg.mining.coinbase_tag_secondary,
        "pool_min_diff": pool.as_ref().map(|p| p.min_difficulty),
        "pool_motd": datum_stats.motd,
        "gateway_fee_bps": cfg.datum.gateway_fee_bps,
        "gateway_fee_address": if cfg.datum.gateway_fee_bps > 0 { json!(cfg.fee_address()) } else { Value::Null },
        "gateway_fee_collected": {"count": server.fee_share_count.load(Ordering::Relaxed), "diff": server.fee_share_diff.load(Ordering::Relaxed)},
        "stratum": {
            "listening": server.listening.load(Ordering::Relaxed),
            "connections": server.connection_count(),
            "subscriptions": server.subscriber_count(),
            "hashrate_ths": server.total_hashrate_ths(),
        },
        "job": job,
        "coinbaser": coinbaser,
        "clients": clients,
        "csrf": if with_clients { json!(ctx.csrf) } else { json!(null) },
    })
}

use serde_json::Value;

fn seconds_or_dash(i: Option<std::time::Instant>) -> String {
    i.map_or("-".to_string(), |t| format!("{}s", t.elapsed().as_secs()))
}

fn clients_page(ctx: &Context) -> String {
    let cfg = &ctx.server.config;
    let mut rows = String::new();
    let mut total = 0.0;
    for c in ctx.server.client_stats() {
        let unpayable = cfg.stratum.require_address_username
            && !crate::address::username_is_payable(&c.username);
        let reject_pct = if c.accepted_diff + c.rejected_diff > 0 {
            100.0 * c.rejected_diff as f64 / (c.accepted_diff + c.rejected_diff) as f64
        } else {
            0.0
        };
        let hr = c.hashrate_ths();
        total += hr.unwrap_or(0.0);
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}{}</td><td>{:08x} {}</td><td>{}</td><td>{}</td><td>{} ({})</td><td>{} ({}) {:.1}%</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><form method=\"post\" action=\"/cmd\"><input type=\"hidden\" name=\"csrf\" value=\"{}\"><input type=\"hidden\" name=\"kill_client\" value=\"{}\"><button>Kick</button></form></td></tr>",
            escape(&c.remote),
            escape(&c.username),
            if unpayable { " (unpayable, shares rejected)" } else { "" },
            c.sid,
            seconds_or_dash(c.subscribed_at),
            seconds_or_dash(c.last_accepted),
            c.current_diff,
            c.accepted_diff,
            c.accepted_count,
            c.rejected_diff,
            c.rejected_count,
            reject_pct,
            if cfg.datum.gateway_fee_bps > 0 { format!("{} ({})", c.fee_diff, c.fee_count) } else { "N/A".to_string() },
            hr.map_or("-".to_string(), |h| format!("{h:.3} Th/s")),
            crate::coinbase::TYPE_NAMES.get(c.coinbase_selection as usize).unwrap_or(&"?"),
            escape(&c.useragent),
            ctx.csrf,
            c.unique_id,
        ));
    }
    page(
        "Stratum Clients",
        &format!(
            "<table><tr><th>RemHost</th><th>Auth Username</th><th>Subbed</th><th>Last Accepted</th><th>VDiff</th><th>DiffA (A)</th><th>DiffR (R)</th><th>Fee DiffA (A)</th><th>Hashrate</th><th>Coinbase</th><th>UserAgent</th><th></th></tr>{rows}</table><p>Total active hashrate estimate: {total:.3} Th/s</p>"
        ),
    )
}

fn coinbaser_page(ctx: &Context) -> String {
    let Some(job) = ctx.server.current_job() else { return page("Coinbaser", "<p>No job.</p>") };
    let mut rows = String::new();
    let mut sum = 0u64;
    for o in &job.coinbaser_outputs {
        sum += o.value;
        rows.push_str(&format!(
            "<tr><td>{:.8}</td><td>{}</td></tr>",
            o.value as f64 / 1e8,
            escape(&crate::address::output_script_to_display(&o.script))
        ));
    }
    if sum < job.template.coinbase_value {
        rows.push_str(&format!(
            "<tr><td>{:.8}</td><td>{} (remainder)</td></tr>",
            (job.template.coinbase_value - sum) as f64 / 1e8,
            escape(&crate::address::output_script_to_display(&job.pool_addr_script))
        ));
    }
    page(
        "Coinbaser",
        &format!("<table><tr><th>Value (BTC)</th><th>Address</th></tr>{rows}</table>"),
    )
}

fn query_param(url: &str, key: &str) -> Option<String> {
    let q = url.split_once('?')?.1;
    for pair in q.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == key {
            return Some(url_decode(v));
        }
    }
    None
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(v);
                    i += 2;
                } else {
                    out.push(b'%');
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn miner_lookup_json(ctx: &Context, addr: Option<&str>) -> serde_json::Value {
    let cfg = &ctx.server.config;
    let valid = addr.filter(|a| a.len() < 128 && crate::address::is_valid(a));
    let mut connections = Vec::new();
    let (mut ad, mut ac, mut rd, mut rc, mut fd, mut fc, mut hr) =
        (0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0f64);
    if let Some(a) = valid {
        for c in ctx.server.client_stats() {
            if !c.subscribed || crate::address::username_address(&c.username) != a {
                continue;
            }
            let h = c.hashrate_ths().unwrap_or(0.0);
            ad += c.accepted_diff;
            ac += c.accepted_count;
            rd += c.rejected_diff;
            rc += c.rejected_count;
            fd += c.fee_diff;
            fc += c.fee_count;
            hr += h;
            connections.push(json!({
                "connected_seconds": c.subscribed_at.map_or(0.0, |t| t.elapsed().as_secs_f64()),
                "last_accepted_seconds": c.last_accepted.map_or(-1.0, |t| t.elapsed().as_secs_f64()),
                "vardiff": c.current_diff,
                "accepted_diff": c.accepted_diff,
                "accepted_count": c.accepted_count,
                "rejected_diff": c.rejected_diff,
                "rejected_count": c.rejected_count,
                "fee_diff": c.fee_diff,
                "fee_count": c.fee_count,
                "hashrate_ths": h,
            }));
        }
    }
    json!({
        "address": valid,
        "fee_bps": cfg.datum.gateway_fee_bps,
        "fee_address": if cfg.datum.gateway_fee_bps > 0 { cfg.fee_address() } else { "" },
        "connection_count": connections.len(),
        "connections": connections,
        "accepted_diff": ad,
        "accepted_count": ac,
        "rejected_diff": rd,
        "rejected_count": rc,
        "fee_diff": fd,
        "fee_count": fc,
        "accepted_under_address_diff": ad.saturating_sub(fd),
        "hashrate_ths": hr,
        "stratum_port": cfg.stratum.listen_port,
        "require_address_username": cfg.stratum.require_address_username,
        "pool_host": if cfg.datum.pool_host.is_empty() { None } else { Some(format!("{}:{}", cfg.datum.pool_host, cfg.datum.pool_port)) },
    })
}

fn form_field(body: &str, key: &str) -> Option<String> {
    body.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| url_decode(v))
    })
}

fn serve_admin(ctx: &Context, mut req: Request) {
    let url = req.url().to_string();
    let path = url.split('?').next().unwrap_or("/").to_string();
    let method = req.method().clone();
    let response = match (method, path.as_str()) {
        (Method::Get, "/") => {
            if query_param(&url, "format").as_deref() == Some("json") {
                let allowed = authorized(ctx, &req);
                let _ = req.respond(json_response(status_json(ctx, allowed)));
            } else {
                let _ = req.respond(html(INDEX_HTML.to_string()));
            }
            return;
        }
        (Method::Get, "/stats.json") => json_response(status_json(ctx, authorized(ctx, &req))),
        (Method::Get | Method::Post, "/NOTIFY") => {
            ctx.server.notify.raise();
            html("OK".to_string())
        }
        (Method::Get, "/clients") => {
            if !authorized(ctx, &req) {
                unauthorized()
            } else {
                html(clients_page(ctx))
            }
        }
        (Method::Get, "/coinbaser") => html(coinbaser_page(ctx)),
        (Method::Post, "/cmd") => {
            // As in C: no admin password, no commands; and the form's token must match.
            if ctx.server.config.api.admin_password.is_empty() {
                forbidden("Commands require api.admin_password to be set.")
            } else if !authorized(ctx, &req) {
                unauthorized()
            } else {
                let mut body = String::new();
                let _ = req.as_reader().take(1 << 20).read_to_string(&mut body);
                if !form_field(&body, "csrf").is_some_and(|t| secure_eq(&t, &ctx.csrf)) {
                    let _ = req.respond(forbidden("Missing or stale form token."));
                    return;
                }
                if let Some(id) =
                    form_field(&body, "kill_client").and_then(|v| v.parse::<u64>().ok())
                {
                    if ctx.server.kill_client(id) {
                        info!("API kill request for client {id}");
                    }
                } else if form_field(&body, "empty_thread").is_some() {
                    ctx.server.shutdown_all();
                }
                let back = req
                    .headers()
                    .iter()
                    .find(|h| h.field.equiv("Referer"))
                    .map(|h| h.value.as_str().to_string())
                    .filter(|r| r.ends_with("/clients"))
                    .map_or("/", |_| "/clients");
                let mut r = Response::from_string("").with_status_code(302);
                r.add_header(Header::from_bytes("Location", back).unwrap());
                r
            }
        }
        (Method::Get | Method::Post, _) => {
            Response::from_string("<H1>Not found</H1>").with_status_code(404)
        }
        _ => Response::from_string("<H1>Method not allowed.</H1>").with_status_code(405),
    };
    let _ = req.respond(response);
}

use std::io::Read as _;

fn serve_miner(ctx: &Context, req: Request) {
    let url = req.url().to_string();
    let path = url.split('?').next().unwrap_or("/").to_string();
    if *req.method() != Method::Get {
        let _ = req
            .respond(Response::from_string("<H1>Method not allowed.</H1>").with_status_code(405));
        return;
    }
    if path != "/" {
        let _ = req.respond(Response::from_string("<H1>Not found</H1>").with_status_code(404));
        return;
    }
    if query_param(&url, "format").as_deref() == Some("json") {
        let addr = query_param(&url, "addr");
        let _ = req.respond(json_response(miner_lookup_json(ctx, addr.as_deref())));
    } else {
        let _ = req.respond(html(MINER_HTML.to_string()));
    }
}

/// Bind on `addr`, or on every address (IPv6 and IPv4, then IPv4 alone if the dual-stack
/// bind fails) when it is empty, as the stratum listener does.
fn bind(addr: &str, port: u16) -> Option<tiny_http::Server> {
    let candidates = if addr.is_empty() {
        vec![format!("[::]:{port}"), format!("0.0.0.0:{port}")]
    } else {
        vec![format!("{addr}:{port}")]
    };
    let mut last = None;
    for bind_addr in &candidates {
        match tiny_http::Server::http(bind_addr) {
            Ok(s) => return Some(s),
            Err(e) => last = Some(format!("{bind_addr}: {e}")),
        }
    }
    warn!("could not bind the API on {}", last.unwrap_or_default());
    None
}

pub fn start(ctx: Arc<Context>) {
    let cfg = Arc::clone(&ctx.server.config);
    if cfg.api.listen_port == 0 {
        info!("No API port configured. API disabled.");
    } else if let Some(server) = bind(&cfg.api.listen_addr, cfg.api.listen_port) {
        info!("API listening on port {}", cfg.api.listen_port);
        let ctx = Arc::clone(&ctx);
        std::thread::Builder::new()
            .name("api".into())
            .spawn(move || {
                for req in server.incoming_requests() {
                    serve_admin(&ctx, req);
                }
            })
            .expect("api thread");
    }
    if cfg.api.miner_listen_port != 0
        && let Some(server) = bind(&cfg.api.miner_listen_addr, cfg.api.miner_listen_port)
    {
        info!("Miner lookup API listening on port {}", cfg.api.miner_listen_port);
        std::thread::Builder::new()
            .name("api-miner".into())
            .spawn(move || {
                for req in server.incoming_requests() {
                    serve_miner(&ctx, req);
                }
            })
            .expect("api miner thread");
    }
}
