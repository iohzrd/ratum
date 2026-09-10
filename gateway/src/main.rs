mod address;
mod api;
mod coinbase;
mod config;
mod datum;
mod dupes;
mod job;
mod logger;
mod publish;
mod settings;
#[cfg(unix)]
mod signals;
mod stratum;
mod submit;
mod tally;
mod template;
mod username;
mod vardiff;

use clap::Parser;
use config::Config;
use log::{error, info, warn};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const WATCH_TICK: Duration = Duration::from_millis(20);
const STATS_INTERVAL: Duration = Duration::from_secs(300);
const FIRST_JOB_PATIENCE: Duration = Duration::from_secs(25);
const NO_JOB_REPORT_INTERVAL: Duration = Duration::from_secs(5);
const POOL_CONNECT_WAIT: Duration = Duration::from_secs(15);
const POOL_CONNECT_POLL: Duration = Duration::from_millis(250);
const FAILURES_BEFORE_SHUTDOWN: u32 = 2;

#[derive(Parser)]
#[command(name = "ratum-gateway", version = ratum::VERSION, about = "DATUM Gateway for the Bitcoin Knots BLAKE2b hardfork")]
struct Cli {
    #[arg(short = 'c', long = "config", default_value = "datum_gateway_config.json")]
    config: String,
}

#[derive(Clone)]
struct Runtime {
    config: Arc<Config>,
    node: ratum::rpc::Client,
    notify: Arc<template::Notify>,
    pool: Arc<datum::Pool>,
}

fn install_panic_exit() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default(info);
        error!("*** PANIC TRIGGERED: EXITING IMMEDIATELY *** {info}");
        log::logger().flush();
        std::process::exit(1);
    }));
}

fn load_config(path: &str) -> Config {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error reading config file {path}: {e}. Check --help");
            std::process::exit(1);
        }
    };
    match Config::parse(&text) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading config file: {e}");
            std::process::exit(1);
        }
    }
}

fn connect_node(config: &Config) -> ratum::rpc::Client {
    let b = &config.bitcoind;
    let node = if b.rpcuser.is_empty() {
        ratum::rpc::Client::with_cookie(&b.rpcurl, b.rpccookiefile.clone().into())
    } else {
        ratum::rpc::Client::new(&b.rpcurl, &b.rpcuser, &b.rpcpassword)
    };
    node.unwrap_or_else(|e| {
        error!("bitcoind.rpcurl: {e}");
        std::process::exit(1);
    })
}

fn start_datum(rt: &Runtime) {
    let identity = ratum::datum::handshake::KeyPairs::generate();
    info!(
        "DATUM gateway identity: {}{}",
        hex::encode(identity.sign_pk),
        hex::encode(identity.box_pk)
    );
    let settings = datum::Settings::from_config(&rt.config);
    let pool = Arc::clone(&rt.pool);
    ratum::thread::spawn("datum", move || datum::run_forever(settings, pool, identity));
    let started = Instant::now();
    let mut last_report = 0;
    while started.elapsed() < POOL_CONNECT_WAIT && !rt.pool.is_active() {
        std::thread::sleep(POOL_CONNECT_POLL);
        let waited = started.elapsed().as_secs();
        if waited != last_report {
            last_report = waited;
            info!("Waiting for the DATUM pool connection ({waited}s)");
        }
    }
    if !rt.pool.is_active() && rt.config.datum.pooled_mining_only {
        error!(
            "Could not connect to the DATUM pool within {} seconds; datum.pooled_mining_only is set, so no work is served until it connects",
            POOL_CONNECT_WAIT.as_secs()
        );
    }
}

fn spawn_stratum_listener(server: Arc<stratum::Server>) {
    ratum::thread::spawn("stratum-listener", move || {
        if let Err(e) = stratum::listen(server) {
            error!("stratum listener: {e}");
            std::process::exit(1);
        }
    });
}

fn start_template_thread(
    rt: &Runtime,
    server: Arc<stratum::Server>,
    last_error: Arc<template::LastError>,
) {
    let rt = rt.clone();
    ratum::thread::spawn("template", move || {
        let publisher = publish::Publisher::new(
            job::Builder::new(Arc::clone(&rt.config)),
            Arc::clone(&server),
            Arc::clone(&rt.pool),
        );
        let mut listener_started = false;
        let (pool, config) = (Arc::clone(&rt.pool), Arc::clone(&rt.config));
        let payout_script =
            move || pool.payout_script().unwrap_or_else(|| config.pool_output_script.clone());
        template::run(
            rt.node.clone(),
            Arc::clone(&rt.config),
            Arc::clone(&rt.notify),
            last_error,
            payout_script,
            |t, new_block| {
                publisher.on_template(t, new_block);
                if !listener_started {
                    listener_started = true;
                    spawn_stratum_listener(Arc::clone(&server));
                }
            },
        );
    });
}

fn due(last: &mut Instant, interval: Duration) -> bool {
    if last.elapsed() < interval {
        return false;
    }
    *last = Instant::now();
    true
}

fn report_missing_job(server: &stratum::Server, started: Instant, last_report: &mut Instant) {
    if server.current_job().is_some() || started.elapsed() <= FIRST_JOB_PATIENCE {
        return;
    }
    if due(last_report, NO_JOB_REPORT_INTERVAL) {
        error!(
            "Did not see an initial stratum job after ~{} seconds. Is your node properly setup?",
            started.elapsed().as_secs()
        );
    }
}

fn report_stats(server: &stratum::Server, last: &mut Instant) {
    if !due(last, STATS_INTERVAL) {
        return;
    }
    let s = server.summary();
    info!(
        "Server stats: {} client{} / {:.2} Th/s",
        s.subscribed,
        if s.subscribed == 1 { "" } else { "s" },
        s.hashrate_ths
    );
}

fn enforce_pooled_only(rt: &Runtime, server: &stratum::Server, warned: &mut bool) {
    let active = rt.pool.is_active();
    if active {
        rt.pool.failures.store(0, Ordering::Relaxed);
    }
    let reject = rt.config.datum.pooled_mining_only && !active;
    if !reject {
        *warned = false;
    } else if !*warned && rt.pool.failures.load(Ordering::Relaxed) >= FAILURES_BEFORE_SHUTDOWN {
        warn!(
            "The DATUM pool is unreachable and datum.pooled_mining_only is set: disconnecting stratum clients until it is reached again"
        );
        server.shutdown_all();
        *warned = true;
    }
    server.rejecting.store(reject, Ordering::Relaxed);
}

fn watch_loop(rt: &Runtime, server: &stratum::Server) -> ! {
    let pooled = !rt.config.datum.pool_host.is_empty();
    let started = Instant::now();
    let mut warned = false;
    let mut last_stats = Instant::now();
    let mut last_no_job_report = Instant::now();
    loop {
        std::thread::sleep(WATCH_TICK);
        report_missing_job(server, started, &mut last_no_job_report);
        report_stats(server, &mut last_stats);
        if pooled {
            enforce_pooled_only(rt, server, &mut warned);
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let config = Arc::new(load_config(&cli.config));
    let notes = logger::init(&config.logger).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });
    info!("ratum-gateway {} starting", ratum::VERSION);
    for (level, message) in notes.iter().chain(&config.warnings) {
        log::log!(*level, "{message}");
    }
    install_panic_exit();
    let node = connect_node(&config);

    if config.datum.gateway_fee_bps > 0 {
        info!(
            "Gateway fee: {} basis points ({:.2}%) of submitted share work, credited to {}",
            config.datum.gateway_fee_bps,
            f64::from(config.datum.gateway_fee_bps) * 100.0 / ratum::BASIS_POINTS_PER_UNIT as f64,
            config.fee_address()
        );
    }

    let notify = Arc::new(template::Notify::default());
    let pool = Arc::new(datum::Pool::new(
        config.datum.protocol_job_slots,
        config.share_queue_capacity(),
        Arc::clone(&notify),
        Some(node.clone()),
    ));
    #[cfg(unix)]
    signals::install(Arc::clone(&notify));
    let rt = Runtime { config, node, notify, pool };
    if rt.config.datum.pool_host.is_empty() {
        info!("NON-POOLED MINING: datum.pool_host is empty; every block pays mining.pool_address");
    } else {
        start_datum(&rt);
    }

    let server = stratum::Server::new(
        Arc::clone(&rt.config),
        Arc::clone(&rt.pool),
        rt.node.clone(),
        Arc::clone(&rt.notify),
    );
    let template_error: Arc<template::LastError> = Arc::default();

    if rt.config.bitcoind.notify_fallback {
        let (node, notify) = (rt.node.clone(), Arc::clone(&rt.notify));
        ratum::thread::spawn("notify-fallback", move || template::fallback_notifier(node, notify));
    }

    api::start(Arc::new(api::Context {
        server: Arc::clone(&server),
        template_error: Arc::clone(&template_error),
        started: Instant::now(),
        csrf: api::csrf_token(),
        config_path: cli.config,
        history: Mutex::default(),
    }));
    start_template_thread(&rt, Arc::clone(&server), template_error);
    watch_loop(&rt, &server)
}
