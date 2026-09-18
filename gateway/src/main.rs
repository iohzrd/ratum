//! `ratum-gateway`: it builds work from a local node's block templates, serves that work to BLAKE2b
//! hardware over stratum, takes the coinbase payout split from the pool over DATUM, and submits the
//! blocks its miners find. This file starts the threads each of those runs on.

mod api;
mod config;
mod datum;
#[cfg(test)]
mod fixtures;
mod gateway;
mod job;
mod logger;
mod node;
mod publish;
mod seen_shares;
#[cfg(unix)]
mod signals;
mod stratum;
mod submit_block;
mod tally;
mod template;
mod username;
mod vardiff;
mod watch;

use clap::Parser;
use config::Config;
use gateway::Gateway;
use log::{error, info};
use ratum::datum::keys::{KeyPairs, PublicKeys};
use std::sync::Arc;
use std::time::{Duration, Instant};

const VERSION: &str = ratum::version!();
const GIT_COMMIT: &str = env!("RATUM_GIT_COMMIT");

const POOL_CONNECT_WAIT: Duration = Duration::from_secs(15);
const POOL_CONNECT_POLL: Duration = Duration::from_millis(250);

#[derive(Parser)]
#[command(name = "ratum-gateway", version = VERSION, about = "DATUM Gateway for the Bitcoin Knots BLAKE2b hardfork")]
struct Cli {
    #[arg(short = 'c', long = "config", default_value = "datum_gateway_config.json")]
    config: String,
}

pub(crate) fn fatal(message: impl std::fmt::Display) -> ! {
    if log::max_level() == log::LevelFilter::Off {
        eprintln!("{message}");
    } else {
        error!("{message}");
        log::logger().flush();
    }
    std::process::exit(1);
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
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| fatal(format!("Error reading config file {path}: {e}. Check --help")));
    Config::parse(&text).unwrap_or_else(|e| fatal(format!("Error reading config file: {e}")))
}

fn connect_node(config: &Config) -> ratum::rpc::Client {
    let b = &config.bitcoind;
    let cookie = (!b.rpccookiefile.is_empty()).then(|| b.rpccookiefile.clone().into());
    ratum::rpc::Client::new(&b.rpcurl, &b.rpcuser, &b.rpcpassword, cookie)
        .unwrap_or_else(|e| fatal(format!("bitcoind.rpcurl: {e}")))
}

fn start_datum(gateway: &Arc<Gateway>, pool_pubkey: PublicKeys) {
    let identity = KeyPairs::generate();
    info!("DATUM gateway identity: {}", identity.public().to_hex());
    let owned = Arc::clone(gateway);
    ratum::thread::spawn("datum", move || datum::run_forever(&owned, pool_pubkey, identity));
    let started = Instant::now();
    let mut last_report = 0;
    while started.elapsed() < POOL_CONNECT_WAIT && !gateway.pool.is_active() {
        std::thread::sleep(POOL_CONNECT_POLL);
        let waited = started.elapsed().as_secs();
        if waited != last_report {
            last_report = waited;
            info!("Waiting for the DATUM pool connection ({waited}s)");
        }
    }
    if !gateway.pool.is_active() && gateway.config.datum.pooled_mining_only {
        error!(
            "Could not connect to the DATUM pool within {} seconds; datum.pooled_mining_only is set, so no work is served until it connects",
            POOL_CONNECT_WAIT.as_secs()
        );
    }
}

fn start_template_thread(gateway: Arc<Gateway>) {
    ratum::thread::spawn("template", move || template::poller::run(&gateway));
}

fn main() {
    let cli = Cli::parse();
    let config = load_config(&cli.config);
    let notes = logger::init(&config.logger).unwrap_or_else(|e| fatal(e));
    info!("ratum-gateway {} starting", VERSION);
    for note in notes.iter().chain(&config.startup_notes) {
        log::log!(note.level, "{}", note.message);
    }
    install_panic_exit();
    let node = connect_node(&config);
    let gateway = Gateway::new(config, node);
    #[cfg(unix)]
    signals::install(Arc::clone(&gateway));
    match gateway.config.pool_pubkey {
        Some(pool_pubkey) => start_datum(&gateway, pool_pubkey),
        None => info!(
            "NON-POOLED MINING: datum.pool_host is empty; every block pays mining.pool_address"
        ),
    }

    node::start_info_thread(Arc::clone(&gateway));

    if gateway.config.bitcoind.notify_fallback {
        let gateway = Arc::clone(&gateway);
        ratum::thread::spawn("notify-fallback", move || {
            template::poller::fallback_notifier(&gateway)
        });
    }

    api::start(Arc::clone(&gateway), cli.config);
    start_template_thread(Arc::clone(&gateway));
    watch::run(&gateway)
}
