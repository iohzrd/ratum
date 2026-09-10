mod snapshot;

use crate::stratum::Server;
use base64::Engine as _;
use log::{info, warn};
use ratum::http::{self, Reply};
use serde_json::{Value, json};
use std::io::Read as _;
use std::sync::{Arc, LazyLock, Mutex};
use tiny_http::{Method, Request};

const CSS: &str = include_str!("page.css");
const JS: &str = include_str!("page.js");

fn assemble(page: &str) -> String {
    page.replace("<!--shared-css-->", &format!("<style>\n{CSS}</style>"))
        .replace("<!--shared-js-->", &format!("<script>\n{JS}</script>"))
}

static INDEX_HTML: LazyLock<String> = LazyLock::new(|| assemble(include_str!("status.html")));
static CONFIG_HTML: LazyLock<String> = LazyLock::new(|| assemble(include_str!("config.html")));

pub struct Context {
    pub server: Arc<Server>,
    pub template_error: Arc<crate::template::LastError>,
    pub started: std::time::Instant,
    pub csrf: String,
    pub config_path: String,
    pub history: Mutex<ratum::hashrate::History>,
}

fn sample_hashrate(ctx: &Context) {
    let hs = ctx.server.summary().hashrate_ths * ratum::HASHES_PER_TERAHASH;
    ratum::hashrate::push_sample(&mut ratum::lock(&ctx.history), ratum::unix_now(), hs);
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

fn authorized(ctx: &Context, req: &Request) -> bool {
    let password = &ctx.server.config.api.admin_password;
    if password.is_empty() {
        return false;
    }
    let Some(value) = http::header_value(req, "Authorization") else { return false };
    let Some(b64) = value.strip_prefix("Basic ") else { return false };
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
    http::text(401, "This action requires admin access.")
        .with_header(http::header("WWW-Authenticate", "Basic realm=\"DATUM Gateway\""))
}

fn redirect(to: &str) -> Reply {
    http::text(302, "").with_header(http::header("Location", to))
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

fn admin_access(ctx: &Context, req: &Request, without_password: &str) -> Result<(), Reply> {
    if ctx.server.config.api.admin_password.is_empty() {
        Err(forbidden(without_password))
    } else if authorized(ctx, req) {
        Ok(())
    } else {
        Err(unauthorized())
    }
}

fn settings_access(ctx: &Context, req: &Request) -> Result<(), Reply> {
    admin_access(ctx, req, "The settings page requires api.admin_password to be set.")
}

fn with_fields(mut base: Value, fields: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    let o = base.as_object_mut().expect("a JSON object");
    o.extend(fields.into_iter().map(|(k, v)| (k.to_string(), v)));
    base
}

fn settings_json(ctx: &Context) -> Value {
    let cfg = &ctx.server.config;
    let doc = std::fs::read_to_string(&ctx.config_path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or(Value::Null);
    with_fields(
        crate::settings::form_values(cfg, &doc),
        [
            ("editable", json!(cfg.api.modify_conf)),
            ("config_path", json!(ctx.config_path)),
            ("csrf", json!(ctx.csrf)),
        ],
    )
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
    match crate::settings::apply(&ctx.server.config, &text, &form) {
        Err(e) => errors(400, e),
        Ok(None) => (http::json(json!({"ok": true, "restart": false})), false),
        Ok(Some(new_text)) => match crate::settings::write_file(&ctx.config_path, &new_text) {
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
    if let Err(reply) = admin_access(ctx, req, "Commands require api.admin_password to be set.") {
        return reply;
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
                http::json(snapshot::status_json(ctx, authorized(ctx, &req)))
            } else {
                http::html(INDEX_HTML.clone())
            }
        }
        (Method::Get, "/stats.json") => {
            http::json(snapshot::status_json(ctx, authorized(ctx, &req)))
        }
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
        crate::settings::restart();
    }
}

fn serve_miner(ctx: &Context, req: Request) {
    let (path, query) = http::path_and_query(&req);
    let response = if *req.method() != Method::Get {
        http::method_not_allowed()
    } else if path != "/" {
        http::not_found()
    } else {
        let addr = http::param(&query, "addr");
        http::json(snapshot::miner_lookup_json(ctx, addr.as_deref()))
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
        let sampler = Arc::clone(&ctx);
        ratum::hashrate::sample_periodically("api-sampler", move || sample_hashrate(&sampler));
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
}
