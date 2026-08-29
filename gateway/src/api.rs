//! The HTTP interfaces: the admin port (`api.listen_port`) serves `status.html` at `/`,
//! which renders `/stats.json` in the browser as the pool's stats page does, plus `/login`,
//! `/cmd` and `/NOTIFY`; the password-less miner lookup is on `api.miner_listen_port`.
//! `/login`, `/cmd` and the client rows of `/stats.json` require `api.admin_password` over
//! HTTP Basic authentication when one is set; the status itself is public, as the C
//! gateway's is. Configuration editing (`api.modify_conf`) is not served.

use crate::stratum::{ClientStats, Server};
use log::{info, warn};
use ratum::http::{self, Reply};
use serde_json::{Value, json};
use std::sync::{Arc, LazyLock, Mutex};
use tiny_http::{Header, Method, Request, Response};

static INDEX_HTML: LazyLock<String> =
    LazyLock::new(|| ratum::web::assemble(include_str!("status.html")));
static MINER_HTML: LazyLock<String> =
    LazyLock::new(|| ratum::web::assemble(include_str!("miner.html")));

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

fn forbidden(why: &str) -> Reply {
    http::text(403, why)
}

fn unauthorized() -> Reply {
    Response::from_string("This action requires admin access.").with_status_code(401).with_header(
        Header::from_bytes("WWW-Authenticate", "Basic realm=\"DATUM Gateway\"").unwrap(),
    )
}

fn redirect(to: &str) -> Reply {
    Response::from_string("")
        .with_status_code(302)
        .with_header(Header::from_bytes("Location", to).unwrap())
}

fn seconds_ago(t: Option<std::time::Instant>) -> f64 {
    t.map_or(-1.0, |t| t.elapsed().as_secs_f64())
}

fn pool_host_json(cfg: &crate::config::Config) -> Value {
    if cfg.datum.pool_host.is_empty() {
        Value::Null
    } else {
        json!(format!("{}:{}", cfg.datum.pool_host, cfg.datum.pool_port))
    }
}

/// `datum.pool_url`, or null when it is not set.
fn pool_url_json(cfg: &crate::config::Config) -> Value {
    if cfg.datum.pool_url.is_empty() { Value::Null } else { json!(cfg.datum.pool_url) }
}

/// One client's row. `identity` adds who it is (the admin's `/stats.json`); the miner
/// lookup reports the counters alone.
fn client_json(cfg: &crate::config::Config, c: &ClientStats, identity: bool) -> Value {
    let mut v = json!({
        "subscribed_seconds": seconds_ago(c.subscribed_at),
        "last_accepted_seconds": seconds_ago(c.last_accepted),
        "vardiff": c.current_diff,
        "accepted_diff": c.accepted.diff,
        "accepted_count": c.accepted.count,
        "rejected_diff": c.rejected.diff,
        "rejected_count": c.rejected.count,
        "fee_diff": c.fee.diff,
        "fee_count": c.fee.count,
        "hashrate_ths": c.hashrate_ths(),
    });
    if identity {
        let o = v.as_object_mut().expect("an object");
        o.insert("id".into(), json!(c.unique_id));
        o.insert("remote".into(), json!(c.remote));
        o.insert("username".into(), json!(c.username));
        o.insert(
            "unpayable".into(),
            json!(
                cfg.stratum.require_address_username
                    && !crate::address::username_is_payable(&c.username)
            ),
        );
        o.insert("useragent".into(), json!(c.useragent));
        o.insert("subscribed".into(), json!(c.subscribed));
        o.insert(
            "coinbase".into(),
            json!(crate::coinbase::TYPE_NAMES.get(c.coinbase_selection as usize).unwrap_or(&"?")),
        );
    }
    v
}

/// The status snapshot. `with_clients` adds the per-connection rows, which need the admin
/// password when one is set.
fn status_json(ctx: &Context, with_clients: bool) -> Value {
    let server = &ctx.server;
    let cfg = &server.config;
    let datum_stats = ratum::lock(&server.datum.stats).clone();
    let pool = server.datum.pool_config();
    let template_error = ratum::lock(&ctx.template_status).error.clone();
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
        // A pool is configured but not connected, and pooled_mining_only is off: the
        // gateway serves work that pays mining.pool_address, as the C gateway does.
        "Non-Pooled Mode (pool unreachable)".to_string()
    };
    let job = current.as_ref().map(|j| {
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
            "txn_total_size": j.template.totals.size,
            "txn_total_weight": j.template.totals.weight,
            "txn_total_sigops": j.template.totals.sigops,
            "is_datum_job": j.is_datum_job,
            "coinbaser_outputs": j.coinbaser_outputs.len(),
        })
    });
    let coinbaser = current.as_ref().map(|j| {
        j.payout_rows()
            .iter()
            .map(|r| {
                json!({
                    "value_btc": r.value as f64 / 1e8,
                    "address": crate::address::output_script_to_display(&r.script),
                    "remainder": r.remainder,
                })
            })
            .collect::<Vec<_>>()
    });
    let clients = with_clients.then(|| {
        server.client_stats().iter().map(|c| client_json(cfg, c, true)).collect::<Vec<_>>()
    });
    let summary = server.summary();
    json!({
        "version": ratum::VERSION,
        "status": status,
        "uptime": duration_text(ctx.started.elapsed()),
        "shares_accepted": datum_stats.accepted.json(),
        "shares_rejected": datum_stats.rejected.json(),
        "pool_host": pool_host_json(cfg),
        "pool_url": pool_url_json(cfg),
        "pool_pubkey": cfg.datum.pool_pubkey,
        "pool_tag": pool.as_ref().map_or(cfg.mining.coinbase_tag_primary.clone(), |p| p.coinbase_tag.clone()),
        "secondary_tag": cfg.mining.coinbase_tag_secondary,
        "pool_min_diff": pool.as_ref().map(|p| p.min_difficulty),
        "pool_motd": datum_stats.motd,
        "gateway_fee_bps": cfg.datum.gateway_fee_bps,
        "gateway_fee_address": if cfg.datum.gateway_fee_bps > 0 { json!(cfg.fee_address()) } else { Value::Null },
        "gateway_fee_collected": ratum::lock(&server.fee).json(),
        "stratum": {
            "listening": server.listening.load(std::sync::atomic::Ordering::Relaxed),
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

/// The counters summed over the connections one address has.
#[derive(Default)]
struct Totals {
    accepted: crate::tally::Tally,
    rejected: crate::tally::Tally,
    fee: crate::tally::Tally,
    hashrate_ths: f64,
}

impl Totals {
    fn add(&mut self, c: &ClientStats) {
        self.accepted.count += c.accepted.count;
        self.accepted.diff += c.accepted.diff;
        self.rejected.count += c.rejected.count;
        self.rejected.diff += c.rejected.diff;
        self.fee.count += c.fee.count;
        self.fee.diff += c.fee.diff;
        self.hashrate_ths += c.hashrate_ths().unwrap_or(0.0);
    }
}

fn miner_lookup_json(ctx: &Context, addr: Option<&str>) -> Value {
    let cfg = &ctx.server.config;
    let valid = addr.filter(|a| a.len() < 128 && crate::address::is_valid(a));
    let clients = valid.map_or_else(Vec::new, |a| {
        ctx.server.client_stats_where(|c| {
            c.subscribed && crate::address::username_address(&c.username) == a
        })
    });
    let mut totals = Totals::default();
    let connections: Vec<Value> = clients
        .iter()
        .map(|c| {
            totals.add(c);
            let mut v = client_json(cfg, c, false);
            // The lookup reports the subscription as the connection's age.
            if let Some(o) = v.as_object_mut()
                && let Some(s) = o.remove("subscribed_seconds")
            {
                o.insert(
                    "connected_seconds".into(),
                    if s.as_f64() == Some(-1.0) { json!(0.0) } else { s },
                );
            }
            v
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
        "pool_url": pool_url_json(cfg),
    })
}

fn serve_admin(ctx: &Context, mut req: Request) {
    let (path, query) = http::path_and_query(&req);
    let method = req.method().clone();
    let response = match (method, path.as_str()) {
        (Method::Get, "/") => {
            if http::param(&query, "format").as_deref() == Some("json") {
                http::json(status_json(ctx, authorized(ctx, &req)))
            } else {
                http::html(INDEX_HTML.clone())
            }
        }
        (Method::Get, "/stats.json") => http::json(status_json(ctx, authorized(ctx, &req))),
        (Method::Get | Method::Post, "/NOTIFY") => {
            ctx.server.notify.raise();
            http::html("OK".to_string())
        }
        // The browser prompts for the admin password on the 401; the status page's client
        // rows then come with the credentials it replays.
        (Method::Get, "/login") => {
            if authorized(ctx, &req) {
                redirect("/")
            } else {
                unauthorized()
            }
        }
        (Method::Post, "/cmd") => {
            // As in C: no admin password, no commands; and the form's token must match.
            if ctx.server.config.api.admin_password.is_empty() {
                forbidden("Commands require api.admin_password to be set.")
            } else if !authorized(ctx, &req) {
                unauthorized()
            } else {
                let mut body = String::new();
                let _ = req.as_reader().take(1 << 20).read_to_string(&mut body);
                if !http::param(&body, "csrf").is_some_and(|t| secure_eq(&t, &ctx.csrf)) {
                    forbidden("Missing or stale form token.")
                } else {
                    if let Some(id) =
                        http::param(&body, "kill_client").and_then(|v| v.parse::<u64>().ok())
                    {
                        if ctx.server.kill_client(id) {
                            info!("API kill request for client {id}");
                        }
                    } else if http::param(&body, "empty_thread").is_some() {
                        ctx.server.shutdown_all();
                    }
                    redirect("/")
                }
            }
        }
        (Method::Get | Method::Post, _) => http::not_found(),
        _ => http::method_not_allowed(),
    };
    let _ = req.respond(response);
}

use std::io::Read as _;

fn serve_miner(ctx: &Context, req: Request) {
    let (path, query) = http::path_and_query(&req);
    let response = if *req.method() != Method::Get {
        http::method_not_allowed()
    } else if path != "/" {
        http::not_found()
    } else if http::param(&query, "format").as_deref() == Some("json") {
        let addr = http::param(&query, "addr");
        http::json(miner_lookup_json(ctx, addr.as_deref()))
    } else {
        http::html(MINER_HTML.clone())
    };
    let _ = req.respond(response);
}

/// Bind on `addr`, or on every address when it is empty, as the stratum listener does.
fn bind(what: &str, addr: &str, port: u16) -> Option<tiny_http::Server> {
    match http::bind(addr, port) {
        Ok(s) => Some(s),
        Err(e) => {
            warn!("could not bind the {what} on {e}");
            None
        }
    }
}

pub fn start(ctx: Arc<Context>) {
    let cfg = Arc::clone(&ctx.server.config);
    if cfg.api.listen_port == 0 {
        info!("No API port configured. API disabled.");
    } else if let Some(server) = bind("API", &cfg.api.listen_addr, cfg.api.listen_port) {
        info!("API listening on port {}", cfg.api.listen_port);
        let ctx = Arc::clone(&ctx);
        http::serve("api", server, move |req| serve_admin(&ctx, req));
    }
    if cfg.api.miner_listen_port != 0
        && let Some(server) =
            bind("miner lookup API", &cfg.api.miner_listen_addr, cfg.api.miner_listen_port)
    {
        info!("Miner lookup API listening on port {}", cfg.api.miner_listen_port);
        http::serve("api-miner", server, move |req| serve_miner(&ctx, req));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_eq_compares_whole_strings() {
        assert!(secure_eq("abc", "abc"));
        assert!(!secure_eq("abc", "abd"));
        assert!(!secure_eq("abc", "ab"));
        assert!(!secure_eq("", "a"));
        assert!(secure_eq("", ""));
    }

    #[test]
    fn uptime_text() {
        assert_eq!(
            duration_text(std::time::Duration::from_secs(90061)),
            "1 days, 1 hours, 1 minutes, 1 seconds"
        );
    }
}
