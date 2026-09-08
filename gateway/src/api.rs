use crate::stratum::{ClientStats, Server};
use log::{info, warn};
use ratum::http::{self, Reply};
use serde_json::{Value, json};
use std::io::Read as _;
use std::sync::{Arc, LazyLock, Mutex};
use tiny_http::{Header, Method, Request, Response};

static INDEX_HTML: LazyLock<String> =
    LazyLock::new(|| ratum::web::assemble(include_str!("status.html")));
static MINER_HTML: LazyLock<String> =
    LazyLock::new(|| ratum::web::assemble(include_str!("miner.html")));
static CONFIG_HTML: LazyLock<String> =
    LazyLock::new(|| ratum::web::assemble(include_str!("config.html")));

pub struct Context {
    pub server: Arc<Server>,
    pub template_status: Arc<Mutex<crate::template::Status>>,
    pub started: std::time::Instant,
    pub csrf: String,
    pub config_path: String,
    pub history: Mutex<ratum::web::History>,
}

fn sample_hashrate(ctx: &Context) {
    let hs = ctx.server.summary().hashrate_ths * ratum::HASHES_PER_TERAHASH;
    ratum::web::push_sample(&mut ratum::lock(&ctx.history), ratum::unix_now(), hs);
}

const CSRF_TOKEN_BYTES: usize = 16;

pub fn csrf_token() -> String {
    hex::encode(ratum::rand::bytes::<CSRF_TOKEN_BYTES>())
}

fn secure_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut acc = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        acc |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    acc == 0
}

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

fn authorized(ctx: &Context, req: &Request) -> bool {
    let password = &ctx.server.config.api.admin_password;
    if password.is_empty() {
        return false;
    }
    let Some(value) = http::header_value(req, "Authorization") else { return false };
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

fn pool_url_json(cfg: &crate::config::Config) -> Value {
    if cfg.datum.pool_url.is_empty() { Value::Null } else { json!(cfg.datum.pool_url) }
}

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
    }
    v
}

fn job_json(j: &crate::job::Job) -> Value {
    json!({
        "job_id": j.job_id,
        "global_index": j.global_index,
        "created_seconds_ago": j.created.elapsed().as_secs_f64(),
        "height": j.template.height,
        "value_btc": j.template.coinbase_value as f64 / ratum::SATS_PER_BTC,
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
}

fn coinbaser_json(j: &crate::job::Job) -> Vec<Value> {
    j.payout_rows()
        .iter()
        .map(|r| {
            json!({
                "value_btc": r.value as f64 / ratum::SATS_PER_BTC,
                "address": crate::address::output_script_to_display(&r.script),
                "remainder": r.remainder,
            })
        })
        .collect()
}

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
        "Non-Pooled Mode (pool unreachable)".to_string()
    };
    let job = current.as_deref().map(job_json);
    let coinbaser = current.as_deref().map(coinbaser_json);
    let clients = with_clients.then(|| {
        server.client_stats().iter().map(|c| client_json(cfg, c, true)).collect::<Vec<_>>()
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
            "interval_seconds": ratum::web::HISTORY_INTERVAL_SECS,
            "history": ratum::lock(&ctx.history)
                .iter()
                .map(|(at, hs)| json!([at, hs.round()]))
                .collect::<Vec<_>>(),
        },
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

#[derive(Default)]
struct Totals {
    accepted: crate::tally::Tally,
    rejected: crate::tally::Tally,
    fee: crate::tally::Tally,
    hashrate_ths: f64,
}

impl Totals {
    fn add(&mut self, c: &ClientStats) {
        self.accepted.merge(&c.accepted);
        self.rejected.merge(&c.rejected);
        self.fee.merge(&c.fee);
        self.hashrate_ths += c.hashrate_ths().unwrap_or(0.0);
    }
}

fn miner_lookup_json(ctx: &Context, addr: Option<&str>) -> Value {
    let cfg = &ctx.server.config;
    let valid =
        addr.filter(|a| a.len() < crate::address::MAX_ADDRESS_CHARS && crate::address::is_valid(a));
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

const MAX_BODY_BYTES: u64 = 1 << 20;

fn read_body(req: &mut Request) -> String {
    let mut body = String::new();
    let _ = req.as_reader().take(MAX_BODY_BYTES).read_to_string(&mut body);
    body
}

fn json_status(code: u16, v: Value) -> Reply {
    http::json(v).with_status_code(code)
}

fn settings_access(ctx: &Context, req: &Request) -> Result<(), Reply> {
    if ctx.server.config.api.admin_password.is_empty() {
        Err(forbidden("The settings page requires api.admin_password to be set."))
    } else if !authorized(ctx, req) {
        Err(unauthorized())
    } else {
        Ok(())
    }
}

fn settings_json(ctx: &Context) -> Value {
    let cfg = &ctx.server.config;
    let doc = std::fs::read_to_string(&ctx.config_path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or(Value::Null);
    let mut v = crate::config::form_values(cfg, &doc);
    let o = v.as_object_mut().expect("an object");
    o.insert("editable".into(), json!(cfg.api.modify_conf));
    o.insert("config_path".into(), json!(ctx.config_path));
    o.insert("csrf".into(), json!(ctx.csrf));
    v
}

fn save_settings(ctx: &Context, body: &str) -> (Reply, bool) {
    let form = http::pairs(body);
    let errors = |code, errors: Vec<String>| {
        (json_status(code, json!({"ok": false, "errors": errors})), false)
    };
    if !form.iter().any(|(k, v)| k == "csrf" && secure_eq(v, &ctx.csrf)) {
        return errors(403, vec!["Missing or stale form token.".into()]);
    }
    let text = match std::fs::read_to_string(&ctx.config_path) {
        Ok(t) => t,
        Err(e) => return errors(500, vec![format!("could not read {}: {e}", ctx.config_path)]),
    };
    match crate::config::apply(&ctx.server.config, &text, &form) {
        Err(e) => errors(400, e),
        Ok(None) => (http::json(json!({"ok": true, "restart": false})), false),
        Ok(Some(new_text)) => match crate::config::write_file(&ctx.config_path, &new_text) {
            Ok(()) => {
                info!("Wrote the new configuration to {}", ctx.config_path);
                (http::json(json!({"ok": true, "restart": true})), true)
            }
            Err(e) => {
                warn!("could not write {}: {e}", ctx.config_path);
                errors(500, vec![format!("could not write {}: {e}", ctx.config_path)])
            }
        },
    }
}

/// Saves the settings form. The bool is whether the process must restart to pick them up.
fn post_settings(ctx: &Context, req: &mut Request) -> (Reply, bool) {
    if !ctx.server.config.api.modify_conf {
        return (forbidden("Saving settings requires api.modify_conf to be set."), false);
    }
    if let Err(reply) = settings_access(ctx, req) {
        return (reply, false);
    }
    let body = read_body(req);
    save_settings(ctx, &body)
}

fn post_command(ctx: &Context, req: &mut Request) -> Reply {
    if ctx.server.config.api.admin_password.is_empty() {
        return forbidden("Commands require api.admin_password to be set.");
    }
    if !authorized(ctx, req) {
        return unauthorized();
    }
    let body = read_body(req);
    if !http::param(&body, "csrf").is_some_and(|t| secure_eq(&t, &ctx.csrf)) {
        return forbidden("Missing or stale form token.");
    }
    if let Some(id) = http::param(&body, "kill_client").and_then(|v| v.parse::<u64>().ok()) {
        if ctx.server.kill_client(id) {
            info!("API kill request for client {id}");
        }
    } else if http::param(&body, "empty_thread").is_some() {
        ctx.server.shutdown_all();
    }
    redirect("/")
}

fn serve_admin(ctx: &Context, mut req: Request) {
    let (path, query) = http::path_and_query(&req);
    let method = req.method().clone();
    let mut restart = false;
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
        (Method::Get, "/login") => {
            if authorized(ctx, &req) {
                redirect("/")
            } else {
                unauthorized()
            }
        }
        (Method::Get, "/config") => match settings_access(ctx, &req) {
            Ok(()) => http::html(CONFIG_HTML.clone()),
            Err(reply) => reply,
        },
        (Method::Get, "/config.json") => match settings_access(ctx, &req) {
            Ok(()) => http::json(settings_json(ctx)),
            Err(reply) => reply,
        },
        (Method::Post, "/config") => {
            let (reply, r) = post_settings(ctx, &mut req);
            restart = r;
            reply
        }
        (Method::Post, "/cmd") => post_command(ctx, &mut req),
        (Method::Get | Method::Post, _) => http::not_found(),
        _ => http::method_not_allowed(),
    };
    let _ = req.respond(response);
    if restart {
        crate::config::restart();
    }
}

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
        sample_hashrate(&ctx);
        let sampler = Arc::clone(&ctx);
        std::thread::Builder::new()
            .name("api-sampler".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(
                        ratum::web::HISTORY_INTERVAL_SECS,
                    ));
                    sample_hashrate(&sampler);
                }
            })
            .expect("api sampler thread");
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
