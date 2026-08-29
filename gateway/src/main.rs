//! ratum-gateway: the DATUM Gateway for the Bitcoin Knots BLAKE2b hardfork.
//!
//! Threads: the template thread polls the node and builds jobs; the stratum server serves
//! them to mining hardware, one thread per connection; the DATUM thread holds the pool
//! connection; the API threads serve HTTP. `main` starts them and then runs the watch loop:
//! the `pooled_mining_only` check, the first-job diagnostic, the periodic statistics line.

mod address;
mod api;
mod coinbase;
mod config;
mod datum;
mod dupes;
mod job;
mod logger;
mod publish;
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

/// How often the watch loop runs.
const WATCH_TICK: Duration = Duration::from_millis(20);
/// The statistics line's interval (the C gateway's 600 half-second ticks).
const STATS_INTERVAL: Duration = Duration::from_secs(300);
/// After this long without a first job the watch loop reports it, then every 5 s.
const FIRST_JOB_PATIENCE: Duration = Duration::from_secs(25);
/// How long the first jobs wait for the pool connection, so they are pooled ones.
const POOL_CONNECT_WAIT: Duration = Duration::from_secs(15);

#[derive(Parser)]
#[command(name = "ratum-gateway", version = ratum::VERSION, about = "DATUM Gateway for the Bitcoin Knots BLAKE2b hardfork")]
struct Cli {
    /// The configuration file (the C gateway's JSON schema).
    #[arg(short = 'c', long = "config", default_value = "datum_gateway_config.json")]
    config: String,
}

/// What every thread shares.
#[derive(Clone)]
struct Runtime {
    config: Arc<Config>,
    node: ratum::rpc::Client,
    notify: Arc<template::Notify>,
    shared: Arc<datum::Shared>,
}

/// A panic on any thread ends the process, as the C gateway's `panic_from_thread` does, so a
/// supervisor restarts it instead of a gateway with a dead template or pool thread serving
/// stale work.
fn install_panic_exit() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default(info);
        error!("*** PANIC TRIGGERED: EXITING IMMEDIATELY *** {info}");
        log::logger().flush();
        std::process::exit(1);
    }));
}

/// The configuration file, or exit 1 with the reason on stderr (the logger it configures
/// does not exist yet).
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

/// The node client `bitcoind.*` names, or exit 1.
fn connect_node(config: &Config) -> ratum::rpc::Client {
    let b = &config.bitcoind;
    let node = if !b.rpcuser.is_empty() {
        ratum::rpc::Client::new(&b.rpcurl, &b.rpcuser, &b.rpcpassword)
    } else {
        ratum::rpc::Client::with_cookie(&b.rpcurl, b.rpccookiefile.clone().into())
    };
    node.unwrap_or_else(|e| {
        error!("bitcoind.rpcurl: {e}");
        std::process::exit(1);
    })
}

/// Start the DATUM thread and wait up to `POOL_CONNECT_WAIT` for its configuration.
fn start_datum(rt: &Runtime) {
    let identity = ratum::datum::handshake::KeyPairs::generate();
    info!(
        "DATUM gateway identity: {}{}",
        hex::encode(identity.sign_pk),
        hex::encode(identity.box_pk)
    );
    let settings = datum::Settings::from_config(&rt.config);
    let shared = Arc::clone(&rt.shared);
    std::thread::Builder::new()
        .name("datum".into())
        .spawn(move || datum::run_forever(settings, shared, identity))
        .expect("datum thread");
    let started = Instant::now();
    let mut last_report = 0;
    while started.elapsed() < POOL_CONNECT_WAIT && !rt.shared.is_active() {
        std::thread::sleep(Duration::from_millis(250));
        let waited = started.elapsed().as_secs();
        if waited != last_report {
            last_report = waited;
            info!("Waiting for the DATUM pool connection ({waited}s)");
        }
    }
    if !rt.shared.is_active() && rt.config.datum.pooled_mining_only {
        error!(
            "Could not connect to the DATUM pool within {} seconds; datum.pooled_mining_only is set, so no work is served until it connects",
            POOL_CONNECT_WAIT.as_secs()
        );
    }
}

/// The template thread: builds jobs from each template and publishes them. The stratum
/// listener starts with the first job, as the C gateway's does.
fn start_template_thread(
    rt: &Runtime,
    server: Arc<stratum::Server>,
    status: Arc<Mutex<template::Status>>,
) {
    let rt = rt.clone();
    std::thread::Builder::new()
        .name("template".into())
        .spawn(move || {
            let publisher = publish::Publisher::new(
                job::Builder::new(Arc::clone(&rt.config)),
                Arc::clone(&server),
                Arc::clone(&rt.shared),
            );
            let mut listener_started = false;
            let payout_script = {
                let rt = rt.clone();
                move || {
                    rt.shared
                        .payout_script()
                        .unwrap_or_else(|| rt.config.pool_output_script.clone())
                }
            };
            template::run(
                rt.node.clone(),
                Arc::clone(&rt.config),
                Arc::clone(&rt.notify),
                status,
                payout_script,
                |t, new_block| {
                    publisher.on_template(t, new_block);
                    if !listener_started {
                        listener_started = true;
                        let server = Arc::clone(&server);
                        std::thread::Builder::new()
                            .name("stratum-listener".into())
                            .spawn(move || {
                                if let Err(e) = stratum::listen(server) {
                                    error!("stratum listener: {e}");
                                    std::process::exit(1);
                                }
                            })
                            .expect("stratum listener thread");
                    }
                },
            );
        })
        .expect("template thread");
}

/// The watch loop: the pooled_mining_only check (new connections are refused whenever the
/// pool is not connected, as the C accept loop does; connected miners are disconnected
/// after two connection attempts that did not reach the pool's configuration), the
/// first-job diagnostic, the statistics line.
fn watch_loop(rt: &Runtime, server: &stratum::Server) -> ! {
    let pooled = !rt.config.datum.pool_host.is_empty();
    let started = Instant::now();
    let mut warned = false;
    let mut last_stats = Instant::now();
    let mut last_no_job_report = Instant::now();
    loop {
        std::thread::sleep(WATCH_TICK);
        if server.current_job().is_none()
            && started.elapsed() > FIRST_JOB_PATIENCE
            && last_no_job_report.elapsed() >= Duration::from_secs(5)
        {
            last_no_job_report = Instant::now();
            error!(
                "Did not see an initial stratum job after ~{} seconds. Is your node properly setup?",
                started.elapsed().as_secs()
            );
        }
        if last_stats.elapsed() >= STATS_INTERVAL {
            last_stats = Instant::now();
            let s = server.summary();
            info!(
                "Server stats: {} client{} / {:.2} Th/s",
                s.subscribed,
                if s.subscribed == 1 { "" } else { "s" },
                s.hashrate_ths
            );
        }
        if !pooled {
            continue;
        }
        let active = rt.shared.is_active();
        if active {
            rt.shared.failures.store(0, Ordering::Relaxed);
        }
        let reject = rt.config.datum.pooled_mining_only && !active;
        if reject && rt.shared.failures.load(Ordering::Relaxed) >= 2 && !warned {
            warn!(
                "The DATUM pool is unreachable and datum.pooled_mining_only is set: disconnecting stratum clients until it is reached again"
            );
            server.shutdown_all();
            warned = true;
        }
        if !reject {
            warned = false;
        }
        server.rejecting.store(reject, Ordering::Relaxed);
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
            config.datum.gateway_fee_bps as f64 / 100.0,
            config.fee_address()
        );
    }

    let notify = Arc::new(template::Notify::default());
    let shared = Arc::new(datum::Shared::new(
        config.datum.protocol_job_slots,
        config.share_queue_capacity(),
        Arc::clone(&notify),
    ));
    let rt = Runtime { config, node, notify, shared };
    if rt.config.datum.pool_host.is_empty() {
        info!("NON-POOLED MINING: datum.pool_host is empty; every block pays mining.pool_address");
    } else {
        start_datum(&rt);
    }

    let server = stratum::Server::new(
        Arc::clone(&rt.config),
        Arc::clone(&rt.shared),
        rt.node.clone(),
        Arc::clone(&rt.notify),
    );
    let template_status = Arc::new(Mutex::new(template::Status::default()));

    if rt.config.bitcoind.notify_fallback {
        let (node, notify) = (rt.node.clone(), Arc::clone(&rt.notify));
        std::thread::Builder::new()
            .name("notify-fallback".into())
            .spawn(move || template::fallback_notifier(node, notify))
            .expect("fallback notifier thread");
    }

    api::start(Arc::new(api::Context {
        server: Arc::clone(&server),
        template_status: Arc::clone(&template_status),
        started: Instant::now(),
        csrf: api::csrf_token(),
    }));
    start_template_thread(&rt, Arc::clone(&server), template_status);
    watch_loop(&rt, &server)
}
