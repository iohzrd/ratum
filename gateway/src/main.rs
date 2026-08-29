//! ratum-gateway: the DATUM Gateway for the Bitcoin Knots BLAKE2b hardfork.
//!
//! Threads: the template thread polls the node and builds jobs; the stratum server serves
//! them to mining hardware, one thread per connection; the DATUM thread holds the pool
//! connection; the API threads serve HTTP. `main` starts them and then runs the watch loop:
//! the `pooled_mining_only` check, the signal flags, the periodic statistics line.

mod address;
mod api;
mod coinbase;
mod config;
mod datum;
mod dupes;
mod job;
mod logger;
mod signals;
mod stratum;
mod submit;
mod template;
mod username;
mod vardiff;

use clap::Parser;
use config::Config;
use log::{error, info, warn};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const GIT_COMMIT: &str = env!("RATUM_GIT_COMMIT");
pub const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " (", env!("RATUM_GIT_COMMIT"), ")");

/// How often the watch loop runs. It relays SIGUSR1 to the template thread, which the C
/// gateway's template loop reads every 2.5 ms, so the tick is short.
const WATCH_TICK: Duration = Duration::from_millis(20);
/// The statistics line's interval (the C gateway's 600 half-second ticks).
const STATS_INTERVAL: Duration = Duration::from_secs(300);
/// After this long without a first job the watch loop reports it, then every 5 s.
const FIRST_JOB_PATIENCE: Duration = Duration::from_secs(25);

#[derive(Parser)]
#[command(name = "ratum-gateway", version = VERSION, about = "DATUM Gateway for the Bitcoin Knots BLAKE2b hardfork")]
struct Cli {
    /// The configuration file (the C gateway's JSON schema).
    #[arg(short = 'c', long = "config", default_value = "datum_gateway_config.json")]
    config: String,
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

/// Build the full job for `t` (with the coinbaser's split when there is one) and publish it.
fn publish_full_job(
    builder: &Mutex<job::Builder>,
    server: &stratum::Server,
    t: &Arc<template::Template>,
    pool: Option<&datum::PoolConfig>,
    coinbaser: Option<ratum::datum::messages::CoinbaserResponse>,
) {
    match ratum::lock(builder).build(Arc::clone(t), false, pool, coinbaser) {
        Ok(job) => {
            let job = Arc::new(job);
            server.publish(Arc::clone(&job), false);
            info!(
                "Stratum job {} ready: height {}, {} coinbaser outputs, {}pooled (sent to {} subscribers)",
                job.job_id,
                job.template.height,
                job.coinbaser_outputs.len(),
                if job.is_datum_job { "" } else { "not " },
                server.subscriber_count()
            );
        }
        Err(e) => error!("could not build the stratum job: {e}"),
    }
}

fn warn_about_open_file_limit(max_clients: usize) {
    let Some((soft, hard)) = signals::open_file_limits() else { return };
    let max_clients = max_clients as u64;
    if max_clients > hard {
        warn!(
            "*** NOTE *** Max Stratum clients ({max_clients}) exceeds hard open file limit (Soft: {soft} / Hard: {hard})"
        );
        warn!(
            "*** NOTE *** Adjust max open file hard limit or you WILL run into issues before reaching max clients!"
        );
    } else if max_clients > soft {
        warn!(
            "*** NOTE *** Max Stratum clients ({max_clients}) exceeds open file soft limit (Soft: {soft} / Hard: {hard})"
        );
        warn!(
            "*** NOTE *** You should increase the soft open file limit to prevent issues as you approach max clients!"
        );
    }
}

fn main() {
    let cli = Cli::parse();
    let text = match std::fs::read_to_string(&cli.config) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error reading config file {}: {e}. Check --help", cli.config);
            std::process::exit(1);
        }
    };
    let config = match Config::parse(&text) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("Error reading config file: {e}");
            std::process::exit(1);
        }
    };
    let notes = logger::init(&config.logger);
    info!("ratum-gateway {VERSION} starting");
    for (level, message) in notes.iter().chain(&config.warnings) {
        log::log!(*level, "{message}");
    }
    install_panic_exit();
    signals::install();
    warn_about_open_file_limit(config.stratum.max_clients);

    let node = if !config.bitcoind.rpcuser.is_empty() {
        ratum::rpc::Client::new(
            &config.bitcoind.rpcurl,
            &config.bitcoind.rpcuser,
            &config.bitcoind.rpcpassword,
        )
    } else {
        ratum::rpc::Client::with_cookie(
            &config.bitcoind.rpcurl,
            config.bitcoind.rpccookiefile.clone().into(),
        )
    };
    let node = match node {
        Ok(n) => n,
        Err(e) => {
            error!("bitcoind.rpcurl: {e}");
            std::process::exit(1);
        }
    };

    if config.datum.gateway_fee_bps > 0 {
        info!(
            "Gateway fee: {} basis points ({:.2}%) of submitted share work, credited to {}",
            config.datum.gateway_fee_bps,
            config.datum.gateway_fee_bps as f64 / 100.0,
            config.fee_address()
        );
    }

    let notify = Arc::new(template::Notify::default());
    // The share queue's size is the C gateway's: per-thread clients times the shares each
    // sends in a stale window, sixteen times over.
    let queue_capacity = config.stratum.max_clients_per_thread
        * config.stratum.vardiff_target_shares_min as usize
        * (config.stratum.share_stale_seconds / 60) as usize
        * 16;
    let shared = Arc::new(datum::Shared::new(
        config.datum.protocol_job_slots,
        queue_capacity,
        Arc::clone(&notify),
    ));
    let failures = Arc::new(Mutex::new(0u32));
    let pooled = !config.datum.pool_host.is_empty();
    let identity = ratum::datum::handshake::KeyPairs::generate();
    if pooled {
        let (sign_pk, box_pk) =
            datum::parse_pool_pubkey(&config.datum.pool_pubkey).expect("validated");
        info!(
            "DATUM gateway identity: {}{}",
            hex::encode(identity.sign_pk),
            hex::encode(identity.box_pk)
        );
        let settings = datum::Settings {
            host: config.datum.pool_host.clone(),
            port: config.datum.pool_port,
            pool_sign_pk: sign_pk,
            pool_box_pk: box_pk,
            global_timeout: Duration::from_secs(config.datum.protocol_global_timeout),
            share_ack_timeout: datum::SHARE_ACK_TIMEOUT,
            share_ack_grace: datum::SHARE_ACK_GRACE,
            user_agent: datum::user_agent(),
            pass_full_users: config.datum.pool_pass_full_users,
            pass_workers: config.datum.pool_pass_workers,
            pool_address: config.mining.pool_address.clone(),
        };
        let (shared2, identity2, failures2) =
            (Arc::clone(&shared), identity.clone(), Arc::clone(&failures));
        std::thread::Builder::new()
            .name("datum".into())
            .spawn(move || datum::run_forever(settings, shared2, identity2, failures2))
            .expect("datum thread");
        // Give the pool connection up to 15 seconds so the first jobs are pooled ones.
        let started = Instant::now();
        let mut last_report = 0;
        while started.elapsed() < Duration::from_secs(15) && !shared.is_active() {
            std::thread::sleep(Duration::from_millis(250));
            let waited = started.elapsed().as_secs();
            if waited != last_report {
                last_report = waited;
                info!("Waiting for the DATUM pool connection ({waited}s)");
            }
        }
        if !shared.is_active() && config.datum.pooled_mining_only {
            error!(
                "Could not connect to the DATUM pool within 15 seconds; datum.pooled_mining_only is set, so no work is served until it connects"
            );
        }
    } else {
        info!("NON-POOLED MINING: datum.pool_host is empty; every block pays mining.pool_address");
    }

    let server = stratum::Server::new(
        Arc::clone(&config),
        Arc::clone(&shared),
        node.clone(),
        Arc::clone(&notify),
    );
    let template_status = Arc::new(Mutex::new(template::Status::default()));

    if config.bitcoind.notify_fallback {
        let (n, notify2) = (node.clone(), Arc::clone(&notify));
        std::thread::Builder::new()
            .name("notify-fallback".into())
            .spawn(move || template::fallback_notifier(n, notify2))
            .expect("fallback notifier thread");
    }

    api::start(Arc::new(api::Context {
        server: Arc::clone(&server),
        template_status: Arc::clone(&template_status),
        started: Instant::now(),
        csrf: api::csrf_token(),
    }));

    // The template thread: builds jobs from each template and publishes them. The stratum
    // listener starts with the first job, as the C gateway's does.
    {
        let (server, config2, shared2, notify2, status2) = (
            Arc::clone(&server),
            Arc::clone(&config),
            Arc::clone(&shared),
            Arc::clone(&notify),
            Arc::clone(&template_status),
        );
        let node2 = node.clone();
        std::thread::Builder::new()
            .name("template".into())
            .spawn(move || {
                let builder = Arc::new(Mutex::new(job::Builder::new(Arc::clone(&config2))));
                // Counts the templates passed in; a coinbaser response for any but the
                // latest is discarded.
                let template_serial = Arc::new(std::sync::atomic::AtomicU64::new(0));
                let mut listener_started = false;
                let payout_script = {
                    let shared = Arc::clone(&shared2);
                    let config = Arc::clone(&config2);
                    move || {
                        shared.pool_config().map_or_else(
                            || {
                                address::to_output_script(&config.mining.pool_address)
                                    .unwrap_or_default()
                            },
                            |p| p.payout_script,
                        )
                    }
                };
                template::run(
                    node2,
                    Arc::clone(&config2),
                    notify2,
                    status2,
                    payout_script,
                    |t, new_block| {
                        let serial = template_serial.fetch_add(1, Ordering::SeqCst) + 1;
                        let pool = shared2.pool_config();
                        if new_block {
                            // The C gateway's sequence on a new tip: empty (subsidy-only) work
                            // at once, then full work with the blank coinbase, then the job
                            // with the pool's payout split once the coinbaser responds. Miners
                            // are never left on subsidy-only work while the request is open.
                            match ratum::lock(&builder).build(
                                Arc::clone(&t),
                                true,
                                pool.as_ref(),
                                None,
                            ) {
                                Ok(job) => server.publish(Arc::new(job), true),
                                Err(e) => error!("could not build the new-block job: {e}"),
                            }
                            std::thread::sleep(Duration::from_millis(50));
                            if pool.is_some() {
                                match ratum::lock(&builder).build(
                                    Arc::clone(&t),
                                    false,
                                    pool.as_ref(),
                                    None,
                                ) {
                                    Ok(job) => server.publish(Arc::new(job), false),
                                    Err(e) => error!("could not build the priority job: {e}"),
                                }
                            }
                        }
                        if pool.is_none() {
                            publish_full_job(&builder, &server, &t, None, None);
                        } else {
                            // The coinbaser wait (up to COINBASER_WAIT) runs on its own thread,
                            // as the C gateway's coinbaser thread does, so this thread keeps
                            // polling the node and answering block notifications meanwhile.
                            let (builder, server, shared, t, template_serial) = (
                                Arc::clone(&builder),
                                Arc::clone(&server),
                                Arc::clone(&shared2),
                                Arc::clone(&t),
                                Arc::clone(&template_serial),
                            );
                            let spawned = std::thread::Builder::new()
                                .name("coinbaser".into())
                                .spawn(move || {
                                    let coinbaser = shared.fetch_coinbaser(
                                        t.coinbase_value,
                                        t.prev_hash,
                                        t.reduced_data,
                                    );
                                    if template_serial.load(Ordering::SeqCst) != serial {
                                        info!(
                                            "coinbaser response for a superseded template; not used"
                                        );
                                        return;
                                    }
                                    let pool = shared.pool_config();
                                    // On a new tip the blank full job is already out; without a
                                    // coinbaser there is nothing to replace it with.
                                    if new_block && pool.is_some() && coinbaser.is_none() {
                                        return;
                                    }
                                    publish_full_job(
                                        &builder,
                                        &server,
                                        &t,
                                        pool.as_ref(),
                                        coinbaser,
                                    );
                                });
                            if let Err(e) = spawned {
                                error!("could not start the coinbaser thread: {e}");
                            }
                        }
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

    // The watch loop: the pooled_mining_only check (new connections are refused whenever the
    // pool is not connected, as the C accept loop does; connected miners are disconnected
    // after two connection attempts that did not reach the pool's configuration), the signal
    // flags, the first-job diagnostic, the statistics line.
    let started = Instant::now();
    let mut warned = false;
    let mut last_stats = Instant::now();
    let mut last_no_job_report = Instant::now();
    loop {
        std::thread::sleep(WATCH_TICK);
        if signals::BLOCK.swap(false, Ordering::Relaxed) {
            info!("SIGUSR1 received: block notification");
            notify.raise();
        }
        if logger::REOPEN.swap(false, Ordering::Relaxed) {
            match logger::reopen() {
                Ok(true) => info!("SIGHUP received: log file reopened"),
                Ok(false) => info!("SIGHUP received: no log file to reopen"),
                Err(e) => error!("SIGHUP received: {e}"),
            }
        }
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
            let n = server.subscriber_count();
            info!(
                "Server stats: {n} client{} / {:.2} Th/s",
                if n == 1 { "" } else { "s" },
                server.total_hashrate_ths()
            );
        }
        if !pooled {
            continue;
        }
        let active = shared.is_active();
        let fails = *ratum::lock(&failures);
        if active {
            *ratum::lock(&failures) = 0;
        }
        let reject = config.datum.pooled_mining_only && !active;
        if reject && fails >= 2 && !warned {
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
