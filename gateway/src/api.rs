//! The status and settings interfaces: the admin port serving the status page, /stats.json, the
//! settings page and the commands, and the miner lookup port serving one unauthenticated endpoint.

mod auth;
mod config_form;
mod snapshot;

use crate::gateway::Gateway;
use auth::{admin_access, authorized, secure_eq, settings_access, unauthorized};
use log::{error, info, warn};
use ratum::http::{self, Reply};
use serde_json::{Value, json};
use std::io::Read as _;
use std::sync::{Arc, LazyLock, Mutex};
use tiny_http::{Method, Request};

const CSS: &str = include_str!("api/page.css");
const JS: &str = include_str!("api/page.js");

fn assemble(page: &str) -> String {
    page.replace("<!--shared-css-->", &format!("<style>\n{CSS}</style>"))
        .replace("<!--shared-js-->", &format!("<script>\n{JS}</script>"))
}

static INDEX_HTML: LazyLock<String> = LazyLock::new(|| assemble(include_str!("api/status.html")));
static CONFIG_HTML: LazyLock<String> = LazyLock::new(|| assemble(include_str!("api/config.html")));

pub struct Context {
    pub gateway: Arc<Gateway>,
    pub started_at: std::time::Instant,
    pub csrf_token: String,
    pub config_path: String,
    pub hashrate_history: Arc<Mutex<ratum::hashrate::HashrateHistory>>,
}

const CSRF_TOKEN_BYTES: usize = 16;

fn redirect(to: &str) -> Reply {
    http::text(302, "").with_header(http::header("Location", to))
}

const MAX_BODY_LEN: u64 = 1 << 20;

fn read_body(req: &mut Request) -> String {
    let mut body = String::new();
    let _ = req.as_reader().take(MAX_BODY_LEN).read_to_string(&mut body);
    body
}

fn json_status(code: u16, v: Value) -> Reply {
    http::json(v).with_status_code(code)
}

fn with_fields(mut base: Value, fields: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    let o = base.as_object_mut().expect("a JSON object");
    o.extend(fields.into_iter().map(|(k, v)| (k.to_string(), v)));
    base
}

fn settings_json(ctx: &Context) -> Value {
    let cfg = &ctx.gateway.config;
    let doc = std::fs::read_to_string(&ctx.config_path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or(Value::Null);
    with_fields(
        config_form::form_values(cfg, &doc),
        [
            ("editable", json!(cfg.api.modify_conf)),
            ("config_path", json!(ctx.config_path)),
            ("csrf", json!(ctx.csrf_token)),
        ],
    )
}

/// The reply to a settings post, and whether it wrote a new configuration file, which the
/// caller restarts on once the reply has been sent.
type SettingsResponse = (Reply, bool);

fn save_settings(ctx: &Context, body: &str) -> SettingsResponse {
    let form = http::pairs(body);
    let errors = |code, errors: Vec<String>| {
        (json_status(code, json!({"ok": false, "errors": errors})), false)
    };
    if !form.iter().any(|(k, v)| k == "csrf" && secure_eq(v, &ctx.csrf_token)) {
        return errors(403, vec!["Missing or stale form token.".into()]);
    }
    let text = match std::fs::read_to_string(&ctx.config_path) {
        Ok(t) => t,
        Err(e) => return errors(500, vec![format!("could not read {}: {e}", ctx.config_path)]),
    };
    match config_form::apply(&ctx.gateway.config, &text, &form) {
        Err(e) => errors(400, e),
        Ok(None) => (http::json(json!({"ok": true, "restart": false})), false),
        Ok(Some(new_text)) => match config_form::write_file(&ctx.config_path, &new_text) {
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

fn post_settings(ctx: &Context, req: &mut Request) -> SettingsResponse {
    if !ctx.gateway.config.api.modify_conf {
        return (auth::forbidden("Saving settings requires api.modify_conf to be set."), false);
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
    if !http::param(&body, "csrf").is_some_and(|t| secure_eq(&t, &ctx.csrf_token)) {
        return auth::forbidden("Missing or stale form token.");
    }
    if let Some(id) = http::param(&body, "kill_client").and_then(|v| v.parse::<u64>().ok()) {
        if ctx.gateway.stratum.kill_client(id) {
            info!("API kill request for client {id}");
        }
    } else if http::param(&body, "empty_thread").is_some() {
        ctx.gateway.stratum.shutdown_all();
    }
    redirect("/")
}

fn serve_admin(ctx: &Context, mut req: Request) {
    let (path, _) = http::path_and_query(&req);
    let method = req.method().clone();
    let mut restart_requested = false;
    let response = match (method, path.as_str()) {
        (Method::Get, "/") => http::html(INDEX_HTML.clone()),
        (Method::Get, "/stats.json") => {
            http::json(snapshot::status_json(ctx, authorized(ctx, &req)))
        }
        (Method::Get | Method::Post, "/NOTIFY") => {
            ctx.gateway.template_waker.raise();
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
            let (reply, restart) = post_settings(ctx, &mut req);
            restart_requested = restart;
            reply
        }
        (Method::Post, "/cmd") => post_command(ctx, &mut req),
        (Method::Get | Method::Post, _) => http::not_found(),
        _ => http::method_not_allowed(),
    };
    let _ = req.respond(response);
    if restart_requested {
        restart();
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

pub fn start(gateway: Arc<Gateway>, config_path: String) {
    let ctx = Arc::new(Context {
        gateway,
        started_at: std::time::Instant::now(),
        csrf_token: hex::encode(ratum::rand::bytes::<CSRF_TOKEN_BYTES>()),
        config_path,
        hashrate_history: Arc::default(),
    });
    let api = &ctx.gateway.config.api;
    if api.listen_port == 0 {
        info!("No API port configured. API disabled.");
    } else if let Some(server) = bind("API", &api.listen_addr, api.listen_port) {
        info!("API listening on port {}", api.listen_port);
        let sampled = Arc::clone(&ctx.gateway);
        ratum::hashrate::sample_every(
            "api-sampler",
            Arc::clone(&ctx.hashrate_history),
            move || sampled.stratum.summary().hashrate_hs,
        );
        let admin = Arc::clone(&ctx);
        http::serve("api", server, move |req| serve_admin(&admin, req));
    }
    if api.miner_listen_port != 0
        && let Some(server) =
            bind("miner lookup API", &api.miner_listen_addr, api.miner_listen_port)
    {
        info!("Miner lookup API listening on port {}", api.miner_listen_port);
        let miner = Arc::clone(&ctx);
        http::serve("api-miner", server, move |req| serve_miner(&miner, req));
    }
}

fn restart() -> ! {
    info!("Restarting to apply the new configuration");
    log::logger().flush();
    std::thread::sleep(std::time::Duration::from_millis(500));
    let exe = std::env::current_exe()
        .unwrap_or_else(|_| std::env::args_os().next().map(Into::into).unwrap_or_default());
    let mut cmd = std::process::Command::new(exe);
    cmd.args(std::env::args_os().skip(1));
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        let e = cmd.exec();
        error!("Could not restart: {e}");
        log::logger().flush();
        std::process::exit(1);
    }
    #[cfg(not(unix))]
    {
        match cmd.spawn() {
            Ok(_) => std::process::exit(0),
            Err(e) => {
                error!("Could not restart: {e}");
                log::logger().flush();
                std::process::exit(1);
            }
        }
    }
}
