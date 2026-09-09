mod abw;
mod admin;
mod cli;
mod connection;
mod credit;
mod relay;
mod server;
mod settings;
mod stats;

use admin::LedgerLocation;
use cli::fatal;
use connection::handle;
use log::{error, info, warn};
use ratum::datum::handshake::KeyPairs;
use ratum::datum::messages::ClientConfig;
use ratum::rpc;
use ratum_prime::ledger;
use ratum_prime::verify::{PoolPolicy, ReplayGuard};
use server::{NodeView, OpenConnectionGuard, PayoutPolicy, Resolver, Server, watch_node};
use settings::Settings;
use std::io;
use std::net::TcpListener;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

fn load_or_create_keys(path: &Path) -> io::Result<KeyPairs> {
    if !path.exists() {
        let keys = KeyPairs::generate();
        write_private(path, hex::encode(keys.to_bytes()).as_bytes())?;
        info!("generated new pool keys at {}", path.display());
        return Ok(keys);
    }
    let text = std::fs::read_to_string(path)?;
    let raw =
        hex::decode(text.trim()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    KeyPairs::from_bytes(&raw).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "key file must decode to {} bytes of hex",
                ratum::datum::handshake::KEY_PAIRS_LEN
            ),
        )
    })
}

#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)
}

#[cfg(not(unix))]
fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    std::fs::write(path, data)
}

fn init_logging() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
}

/// Reads the node's chain and difficulty, which name the ledger file and size the share
/// window. Without a ledger file the read may fail and the window starts at its floor;
/// with one the chain must be known, so this waits for the node.
fn startup_chain_and_window(
    node: &rpc::Client,
    location: &LedgerLocation,
    s: &Settings,
) -> (Option<rpc::Chain>, u128) {
    let tip = loop {
        match node.tip() {
            Ok(t) => break Some(t),
            Err(e) if matches!(location, LedgerLocation::None) => {
                warn!(
                    "could not read the node difficulty to size the share window ({e}); \
                     starting from the floor of {}, so shares recorded before this restart \
                     are credited only as far back as that floor reaches",
                    s.window_floor
                );
                break None;
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
    };
    let window = match tip {
        Some(t) => ledger::window_for_difficulty(t.difficulty, s.window_multiple, s.window_floor),
        None => s.window_floor,
    };
    (tip.map(|t| t.chain), window)
}

/// Starts the thread that follows the node's tip, and reports what it will do.
fn watch_node_in_background(
    node: &rpc::Client,
    view: &Arc<NodeView>,
    s: &Settings,
    chain: Option<rpc::Chain>,
) {
    let (watcher, view, poll) = (node.clone(), Arc::clone(view), s.poll);
    std::thread::spawn(move || watch_node(watcher, view, poll, chain));
    info!(
        "watching the node at {}: waiting on each new block, \
         re-reading the tip at least every {:.3}s",
        node.url(),
        s.poll.as_secs_f64()
    );
}

/// The guard against crediting one share twice, seeded with the hashes the ledger holds.
fn replay_guard(ledger: &ledger::Ledger) -> Arc<Mutex<ReplayGuard>> {
    let mut guard = ReplayGuard::default();
    let seeded = ledger.hashes().fold(0usize, |n, h| n + usize::from(guard.accept(*h)));
    if seeded != 0 {
        info!("ReplayGuard seeded with {seeded} share hash(es) from the ledger");
    }
    Arc::new(Mutex::new(guard))
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
        if server.open_connections.fetch_add(1, Ordering::Relaxed) >= server.max_connections {
            server.open_connections.fetch_sub(1, Ordering::Relaxed);
            match stream.peer_addr() {
                Ok(p) => warn!(
                    "[{p}] refused: already serving {} connections (--max-connections)",
                    server.max_connections
                ),
                Err(_) => warn!("refused a connection: at --max-connections"),
            }
            continue;
        }
        let conn = Arc::clone(server);
        if let Err(e) =
            std::thread::Builder::new().name("connection".to_string()).spawn(move || {
                let _open = OpenConnectionGuard(Arc::clone(&conn));
                let peer = stream.peer_addr().ok();
                if let Err(e) = handle(stream, &conn) {
                    match peer {
                        Some(p) => warn!("[{p}] connection error: {e}"),
                        None => warn!("connection error: {e}"),
                    }
                }
            })
        {
            server.open_connections.fetch_sub(1, Ordering::Relaxed);
            error!("could not start a thread for a connection: {e}");
        }
    }
}

fn main() -> io::Result<()> {
    init_logging();
    let loaded = cli::load();
    info!("ratum-prime {}", ratum::VERSION);

    let mut s = Settings::resolve(&loaded.cli, loaded.file);
    if let Some(dir) = &s.data_dir {
        std::fs::create_dir_all(dir)?;
    }
    let ledger_location = LedgerLocation::new(s.ledger_path.clone(), s.data_dir.as_ref());
    if let Some(done) = admin::run_command(&loaded.cli, &ledger_location) {
        return done;
    }

    let pool_keys = load_or_create_keys(&s.key_path)?;
    info!("pool_pubkey: {}", pool_keys.pubkey_hex());

    let node = s.connect_node()?;
    let payout_script = settings::payout_script(&node, s.payout.take());
    info!("pool payout script: {}", hex::encode(&payout_script));

    let (chain, startup_window) = startup_chain_and_window(&node, &ledger_location, &s);
    let node_view = Arc::new(NodeView::new());
    watch_node_in_background(&node, &node_view, &s, chain);

    let ledger = admin::open_share_ledger(
        ledger_location.file_for(chain).as_ref(),
        startup_window,
        s.ledger_keep,
        chain.map(rpc::Chain::name),
    )?;
    info!(
        "payouts: window {}x network difficulty (floor {}, {startup_window} at startup), \
         minimum {} sats, operator fee {} bps",
        s.window_multiple, s.window_floor, s.min_payout, s.fee_bps
    );

    let config = ClientConfig {
        payout_script,
        prime_id: s.prime_id,
        coinbase_tag: s.coinbase_tag,
        min_difficulty: s.min_difficulty,
    };
    let config_payload = match config.encode() {
        Ok(p) => p,
        Err(e) => fatal!("cannot build the client config: {e}"),
    };
    let mut policy = PoolPolicy::from_config(&config);
    policy.require_split = s.require_split;
    if !policy.require_split {
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

    let server = Arc::new(Server {
        pool_keys,
        node_view,
        motd: s.motd,
        allowed_agents: s.allowed_agents,
        require_v3: s.require_v3,
        sessions: Mutex::new(server::SessionStore::default()),
        abw_reveal_after: s.abw_reveal_after,
        replay: replay_guard(&ledger),
        node,
        ledger: Mutex::new(ledger),
        resolver: Mutex::new(Resolver::new()),
        payout: PayoutPolicy {
            min_payout: s.min_payout,
            window_multiple: s.window_multiple,
            window_floor: s.window_floor,
            fee_bps: s.fee_bps,
        },
        policy,
        config_payload,
        open_connections: AtomicUsize::new(0),
        max_connections: s.max_connections,
        datum_port: s.listen.rsplit_once(':').and_then(|(_, p)| p.parse().ok()).unwrap_or(0),
        advertise: s.advertise_address,
        public_gateway: s.public_gateway,
    });

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
