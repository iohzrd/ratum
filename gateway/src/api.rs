//! The status and settings interfaces: the admin port serving the status page, /stats.json, the
//! settings page and the commands, and the miner lookup port serving one unauthenticated endpoint.

mod auth;
mod config_form;
mod snapshot;

use crate::gateway::Gateway;
use auth::{admin_access, authorized, secure_eq, settings_access, unauthorized};
use log::{error, info, warn};
use ratum::http::{self, Method, Reply, Request};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};

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
    failed_logins: auth::FailedLogins,
    /// Held across a settings save's read, edit and write of the file. Requests are served
    /// on concurrent threads, and two saves interleaved there would each write an edit of
    /// the same original, the later discarding the earlier.
    settings_save: Mutex<()>,
    /// The working directory at startup, which a relative argv[0] is resolved against when
    /// the gateway restarts itself.
    startup_dir: Option<PathBuf>,
}

const CSRF_TOKEN_BYTES: usize = 16;

fn redirect(to: &str) -> Reply {
    http::text(302, "").with_header(http::header("Location", to))
}

/// The largest request body the admin port reads; a longer one is answered 413 unread.
const MAX_BODY_LEN: usize = 1 << 20;

fn read_body(req: &Request) -> String {
    String::from_utf8_lossy(&req.body).into_owned()
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
    let _saving = ratum::lock(&ctx.settings_save);
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

fn post_settings(ctx: &Context, req: &Request) -> SettingsResponse {
    if !ctx.gateway.config.api.modify_conf {
        return (auth::forbidden("Saving settings requires api.modify_conf to be set."), false);
    }
    if let Err(reply) = settings_access(ctx, req) {
        return (reply, false);
    }
    let body = read_body(req);
    save_settings(ctx, &body)
}

fn post_command(ctx: &Context, req: &Request) -> Reply {
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

/// Refuses every framing of an admin page by another origin: X-Frame-Options for browsers
/// that predate the Content-Security-Policy directive, and the directive for the rest.
fn deny_framing(reply: Reply) -> Reply {
    reply
        .with_header(http::header("X-Frame-Options", "DENY"))
        .with_header(http::header("Content-Security-Policy", "frame-ancestors 'none'"))
}

fn serve_admin(ctx: &Context, req: &Request) -> Reply {
    let (path, _) = http::path_and_query(req);
    let mut restart_requested = false;
    let response = match (&req.method, path.as_str()) {
        (Method::Get, "/") => http::html(INDEX_HTML.clone()),
        (Method::Get, "/stats.json") => match authorized(ctx, req) {
            Ok(with_clients) => http::json(snapshot::status_json(ctx, with_clients)),
            Err(reply) => reply,
        },
        (Method::Get | Method::Post, "/NOTIFY") => {
            ctx.gateway.template_waker.raise();
            http::html("OK".to_string())
        }
        (Method::Get, "/login") => match authorized(ctx, req) {
            Ok(true) => redirect("/"),
            Ok(false) => unauthorized(),
            Err(reply) => reply,
        },
        (Method::Get, "/config") => match settings_access(ctx, req) {
            Ok(()) => http::html(CONFIG_HTML.clone()),
            Err(reply) => reply,
        },
        (Method::Get, "/config.json") => match settings_access(ctx, req) {
            Ok(()) => http::json(settings_json(ctx)),
            Err(reply) => reply,
        },
        (Method::Post, "/config") => {
            let (reply, restart) = post_settings(ctx, req);
            restart_requested = restart;
            reply
        }
        (Method::Post, "/cmd") => post_command(ctx, req),
        (Method::Get | Method::Post, _) => http::not_found(),
        _ => http::method_not_allowed(),
    };
    let response = deny_framing(response);
    if restart_requested {
        let startup_dir = ctx.startup_dir.clone();
        response.after_sent(move || restart(startup_dir.as_deref()))
    } else {
        response
    }
}

fn serve_miner(ctx: &Context, req: &Request) -> Reply {
    let (path, query) = http::path_and_query(req);
    if req.method != Method::Get {
        http::method_not_allowed()
    } else if path != "/" {
        http::not_found()
    } else {
        let addr = http::param(&query, "addr");
        http::json(snapshot::miner_lookup_json(ctx, addr.as_deref()))
    }
}

fn bind(what: &str, addr: &str, port: u16) -> Option<http::Server> {
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
        failed_logins: auth::FailedLogins::default(),
        settings_save: Mutex::new(()),
        startup_dir: std::env::current_dir().ok(),
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
            // The gateway reads no network estimate, so its samples carry its own rate alone.
            move || (sampled.stratum.summary().hashrate_hs, None),
        );
        let admin = Arc::clone(&ctx);
        http::serve("api", server, MAX_BODY_LEN, move |req| serve_admin(&admin, &req));
    }
    if api.miner_listen_port != 0
        && let Some(server) =
            bind("miner lookup API", &api.miner_listen_addr, api.miner_listen_port)
    {
        info!("Miner lookup API listening on port {}", api.miner_listen_port);
        let miner = Arc::clone(&ctx);
        // The lookup is a GET, so a request carrying a body is refused.
        http::serve("api-miner", server, 0, move |req| serve_miner(&miner, &req));
    }
}

/// The program the gateway runs to restart itself: the path of the running executable, or,
/// when that path no longer exists, argv[0]. On Linux `current_exe` reads /proc/self/exe,
/// which for an executable replaced in place (an upgrade) is the old path with " (deleted)"
/// appended.
fn executable(startup_dir: Option<&Path>) -> PathBuf {
    if let Ok(exe) = std::env::current_exe()
        && exe.exists()
    {
        return exe;
    }
    let argv0 = std::env::args_os().next().map(PathBuf::from).unwrap_or_default();
    resolve_argv0(argv0, startup_dir)
}

/// argv[0] as a path that names the same file from any working directory: a relative path
/// with a directory part is joined to the directory the gateway started in. A bare name (no
/// directory part) is left alone, since the shell found it on PATH and `Command` searches PATH
/// again for it.
fn resolve_argv0(argv0: PathBuf, startup_dir: Option<&Path>) -> PathBuf {
    match startup_dir {
        Some(dir) if argv0.is_relative() && argv0.components().count() > 1 => dir.join(argv0),
        _ => argv0,
    }
}

fn restart(startup_dir: Option<&Path>) -> ! {
    info!("Restarting to apply the new configuration");
    log::logger().flush();
    std::thread::sleep(std::time::Duration::from_millis(500));
    let mut cmd = std::process::Command::new(executable(startup_dir));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relative_argv0_with_a_directory_is_resolved_against_the_startup_directory() {
        let dir = Path::new("/srv/gateway");
        assert_eq!(
            resolve_argv0("./bin/ratum-gateway".into(), Some(dir)),
            PathBuf::from("/srv/gateway/./bin/ratum-gateway")
        );
        assert_eq!(
            resolve_argv0("ratum-gateway".into(), Some(dir)),
            PathBuf::from("ratum-gateway"),
            "a bare name is searched on PATH"
        );
        assert_eq!(
            resolve_argv0("/usr/bin/ratum-gateway".into(), Some(dir)),
            PathBuf::from("/usr/bin/ratum-gateway")
        );
        assert_eq!(resolve_argv0("bin/x".into(), None), PathBuf::from("bin/x"));
    }

    #[test]
    fn admin_replies_refuse_framing() {
        let reply = deny_framing(http::text(200, "ok"));
        assert_eq!(reply.header("X-Frame-Options"), Some("DENY"));
        assert_eq!(reply.header("Content-Security-Policy"), Some("frame-ancestors 'none'"));
    }
}
