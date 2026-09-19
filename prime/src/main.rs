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
mod control;
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
mod txns;
mod verify;

use connection::handle;
use ledger::{Ledger, LedgerLocation};
use log::{debug, error, info, warn};
use node::watch_node;
use ratum::rpc;
use server::Server;
use settings::{Resolved, Settings};
use std::io;
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

const VERSION: &str = ratum::version!();

fn init_logging() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
}

/// The node's tip, read before the ledger opens: its chain names the ledger file and the
/// address prefixes the payout address and every miner's identity must carry, and its
/// difficulty sizes the window read back. A memory-only ledger starts without it when the node
/// does not answer.
fn startup_tip(node: &rpc::Client, location: &LedgerLocation, s: &Settings) -> Option<rpc::Tip> {
    loop {
        match node.tip() {
            Ok(t) => return Some(t),
            Err(e) if matches!(location, LedgerLocation::MemoryOnly) => {
                warn!(
                    "could not read the node difficulty to size the share window ({e}); the \
                     window is sized to a difficulty of 1 until the node answers, and an \
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

/// The pause after an accept error other than a connection the peer aborted. Without it a
/// descriptor limit (EMFILE, ENFILE) would make the listener call accept() without pause.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

fn accept_connections(listener: TcpListener, server: &Arc<Server>) {
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                let aborted = matches!(
                    e.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::ConnectionReset
                );
                if !aborted {
                    error!("could not accept a connection: {e}");
                    std::thread::sleep(ACCEPT_RETRY_DELAY);
                }
                continue;
            }
        };
        let peer = match stream.peer_addr() {
            Ok(p) => p,
            Err(e) => {
                debug!("could not read the address of an accepted connection: {e}");
                continue;
            }
        };
        let open = match Server::open_connection(server, ratum::net::limit_key(peer.ip())) {
            Ok(open) => open,
            Err(limit) => {
                warn!("[{peer}] refused: at {limit}");
                continue;
            }
        };
        let conn = Arc::clone(server);
        // `open` moves into the thread, so a thread that does not start drops it here.
        let spawned = ratum::thread::try_spawn("connection", move || {
            let _open = open;
            if let Err(e) = handle(stream, &conn) {
                warn!("[{peer}] connection error: {e}");
            }
        });
        if let Err(e) = spawned {
            error!("could not start a thread for a connection: {e}");
        }
    }
}

/// Each gateway connection holds its socket and its poller's epoll instance and eventfd.
const FDS_PER_CONNECTION: u64 = 3;
/// The descriptors besides the connections: the ledger, the listeners, the node's RPC
/// connections and the standard streams, with room.
const FDS_BESIDES_CONNECTIONS: u64 = 64;

/// Raises the soft open file limit to the hard limit and warns when `--max-connections` needs
/// more descriptors than it allows.
fn raise_open_file_limit(max_connections: usize) {
    let Some((soft, hard)) = ratum::limits::raise_open_file_limit() else { return };
    info!("open file limit: {soft} (hard limit {hard})");
    let needed =
        FDS_PER_CONNECTION.saturating_mul(max_connections as u64) + FDS_BESIDES_CONNECTIONS;
    if needed > soft {
        let fit = soft.saturating_sub(FDS_BESIDES_CONNECTIONS) / FDS_PER_CONNECTION;
        warn!(
            "--max-connections is {max_connections}, which needs {needed} open files; the open \
             file limit of {soft} fits {fit} connections, and accepting past that fails. Raise \
             the hard limit (ulimit -Hn, or LimitNOFILE= in a systemd unit) or lower \
             --max-connections."
        );
    }
}

fn report_settings(s: &Settings, ledger: &Ledger) {
    let (window, split) = (ledger.window_rule(), ledger.split_policy());
    info!(
        "payouts: window {}x network difficulty ({} at startup), operator fee {} bps",
        window.multiple,
        ledger.window(),
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
    let ledger_location = LedgerLocation::new(s.data_dir.as_deref());
    if let Some(done) = admin::run_command(&options, &ledger_location) {
        return done;
    }

    let pool_keys = keys::load_or_create_keys(&s.key_path())?;
    info!("pool_pubkey: {}", pool_keys.public().to_hex());

    let node = settings::connect_node(&options).unwrap_or_else(|e| cli::fatal!("{e}"));
    let tip = startup_tip(&node, &ledger_location, &s);
    let chain = tip.map(|t| t.chain);
    let share = settings::share_policy(&options, chain).unwrap_or_else(|e| cli::fatal!("{e}"));
    info!("pool payout script: {}", hex::encode(&share.config.payout_script));

    // Bound before the ledger opens, so a second pool on the data directory is refused here,
    // naming this one; dropped when main returns, which removes the socket file. A socket
    // that cannot be bound (a path past the socket path limit, a filesystem that holds no
    // sockets) leaves the pool running without one, as before the socket existed.
    let mut control = match s.data_dir.as_deref().map(control::ControlSocket::bind) {
        Some(Ok(control)) => Some(control),
        Some(Err(e)) if e.kind() == io::ErrorKind::AddrInUse => return Err(e),
        Some(Err(e)) => {
            warn!(
                "no control socket: {e}; the ledger commands run on the ledger file with the \
                 pool stopped"
            );
            None
        }
        None => None,
    };

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
    report_settings(&s, &ledger);

    let server = Arc::new(Server::new(s, share, pool_keys, node, (ledger, records))?);
    let s = &server.settings;
    raise_open_file_limit(s.max_connections);

    watch_node_in_background(&server, chain);
    confirmations::watch(Arc::clone(&server));
    if let Some(control) = &mut control {
        control.serve(Arc::clone(&server));
    }

    if let Some(addr) = &s.stats_listen {
        match stats::spawn(Arc::clone(&server), addr) {
            Ok(bound) => info!("stats interface listening on http://{bound}"),
            Err(e) => error!("stats interface could not start on {addr}: {e}"),
        }
    }

    let listener = ratum::net::listen(&s.listen)?;
    let bound = listener.local_addr().map_or_else(|_| s.listen.clone(), |a| a.to_string());
    info!(
        "listening on {bound} (at most {} connections, {} from one address)",
        s.max_connections, s.max_connections_per_ip
    );
    accept_connections(listener, &server);
    Ok(())
}
