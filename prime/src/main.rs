//! `ratum-prime`: the pool server. It accepts gateway connections, verifies the shares they send
//! against the jobs they carry, credits them to a share window, dictates the coinbase split of that
//! window to every gateway, and submits the blocks it verifies to its node. This file resolves the
//! settings, opens the ledger and starts the threads.

mod abw;
mod accounting;
mod admin;
mod bounded;
mod cli;
mod confirmations;
mod connection;
#[cfg(test)]
mod fixtures;
mod keys;
mod ledger;
mod node;
mod payout;
mod relay;
mod server;
mod sessions;
mod settings;
mod stats;
mod verify;

use connection::handle;
use ledger::{Ledger, LedgerLocation};
use log::{error, info, warn};
use node::watch_node;
use ratum::rpc;
use server::Server;
use settings::{Resolved, Settings};
use std::io;
use std::net::TcpListener;
use std::sync::Arc;
use verify::SharePolicy;

const VERSION: &str = ratum::version!();

fn init_logging() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
}

/// The node's tip, read before the ledger opens: its chain names the ledger file and the
/// address prefixes the payout address and every miner's identity must carry, and its
/// difficulty sizes the window read back. A memory-only ledger starts without it when the node
/// does not answer.
fn startup_tip(
    node: &rpc::Client,
    location: &LedgerLocation,
    s: &Settings,
    window_floor: u128,
) -> Option<rpc::Tip> {
    loop {
        match node.tip() {
            Ok(t) => return Some(t),
            Err(e) if matches!(location, LedgerLocation::MemoryOnly) => {
                warn!(
                    "could not read the node difficulty to size the share window ({e}); \
                     starting from the floor of {window_floor}, so shares recorded before this \
                     restart are credited only as far back as that floor reaches, and an \
                     address with the prefixes of any chain is accepted"
                );
                return None;
            }
            Err(e) => {
                warn!(
                    "could not read the node's chain and difficulty ({e}); the ledger is \
                     named after the chain, so retrying in {:.3}s",
                    s.poll.as_secs_f64()
                );
                std::thread::sleep(s.poll);
            }
        }
    }
}

fn watch_node_in_background(server: &Arc<Server>, chain: Option<rpc::Chain>) {
    let watched = Arc::clone(server);
    ratum::thread::spawn("node-watch", move || watch_node(&watched, chain));
    info!(
        "watching the node at {}: waiting on each new block, \
         re-reading the tip at least every {:.3}s",
        server.node.url(),
        server.settings.poll.as_secs_f64()
    );
}

fn accept_connections(listener: TcpListener, server: &Arc<Server>) {
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                error!("could not accept a connection: {e}");
                continue;
            }
        };
        let Some(open) = Server::open_connection(server) else {
            let max_connections = server.settings.max_connections;
            match stream.peer_addr() {
                Ok(p) => warn!(
                    "[{p}] refused: already serving {max_connections} connections \
                     (--max-connections)"
                ),
                Err(_) => warn!("refused a connection: at --max-connections"),
            }
            continue;
        };
        let conn = Arc::clone(server);
        // `open` moves into the thread, so a thread that does not start drops it here.
        let spawned = ratum::thread::try_spawn("connection", move || {
            let _open = open;
            let peer = stream.peer_addr().ok();
            if let Err(e) = handle(stream, &conn) {
                match peer {
                    Some(p) => warn!("[{p}] connection error: {e}"),
                    None => warn!("connection error: {e}"),
                }
            }
        });
        if let Err(e) = spawned {
            error!("could not start a thread for a connection: {e}");
        }
    }
}

fn report_settings(s: &Settings, share: &SharePolicy, ledger: &Ledger) {
    let (window, split) = (ledger.window_rule(), ledger.split_policy());
    info!(
        "payouts: window {}x network difficulty (floor {}, {} at startup), minimum {} sats, \
         operator fee {} bps",
        window.multiple,
        window.floor,
        ledger.window(),
        split.min_payout,
        split.fee_bps
    );
    if let Some(gateway) = split.public_gateway.as_ref().filter(|g| g.fee_bps > 0) {
        info!(
            "public gateway fee: {} bps of the work of shares carrying the secondary coinbase \
             tag {:?}, of which {} bps is reassigned at each split to miners whose shares do \
             not carry it",
            gateway.fee_bps, gateway.tag, gateway.subsidy_bps
        );
    }
    if !share.require_split {
        info!(
            "--require-split=false: a coinbase paying only the pool script is accepted from any job"
        );
    }
    if !s.allowed_agents.is_empty() {
        info!(
            "gateway user agents restricted to the prefixes {:?}; others are refused at hello",
            s.allowed_agents
        );
    }
    if s.require_v3 {
        info!(
            "version 3 protocol required: a hello without the DRS extension is refused, so \
             every connection is under an anti-block-withholding assignment"
        );
    }
}

fn main() -> io::Result<()> {
    init_logging();
    let options = cli::load();
    info!("ratum-prime {}", VERSION);

    let Resolved { settings: s, window, split } =
        settings::resolve(&options).unwrap_or_else(|e| cli::fatal!("{e}"));
    if let Some(dir) = &s.data_dir {
        std::fs::create_dir_all(dir)?;
    }
    let ledger_location = LedgerLocation::new(s.ledger_path.clone(), s.data_dir.as_deref());
    if let Some(done) = admin::run_command(&options, &ledger_location) {
        return done;
    }

    let pool_keys = keys::load_or_create_keys(&s.key_path)?;
    info!("pool_pubkey: {}", pool_keys.public().to_hex());

    let node = settings::connect_node(&options).unwrap_or_else(|e| cli::fatal!("{e}"));
    let tip = startup_tip(&node, &ledger_location, &s, window.floor);
    let chain = tip.map(|t| t.chain);
    let share = settings::share_policy(&options, chain).unwrap_or_else(|e| cli::fatal!("{e}"));
    info!("pool payout script: {}", hex::encode(&share.config.payout_script));

    let mut ledger = Ledger::new(window, split);
    if let Some(t) = tip {
        ledger.set_network_difficulty(t.difficulty);
    }
    let (ledger, records) = ledger::open_share_ledger(
        ledger_location.file_for(chain)?.as_deref(),
        s.ledger_keep_shares,
        chain.map(rpc::Chain::name),
        ledger,
    )?;
    report_settings(&s, &share, &ledger);

    let server = Arc::new(Server::new(s, share, pool_keys, node, (ledger, records))?);
    let s = &server.settings;

    watch_node_in_background(&server, chain);
    confirmations::watch(Arc::clone(&server));

    if let Some(addr) = &s.stats_listen {
        match stats::spawn(Arc::clone(&server), addr) {
            Ok(bound) => info!("stats interface listening on http://{bound}"),
            Err(e) => error!("stats interface could not start on {addr}: {e}"),
        }
    }

    let listener = TcpListener::bind(&s.listen)?;
    let bound = listener.local_addr().map_or_else(|_| s.listen.clone(), |a| a.to_string());
    info!("listening on {bound} (at most {} connections)", s.max_connections);
    accept_connections(listener, &server);
    Ok(())
}
