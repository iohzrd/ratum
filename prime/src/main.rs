mod cli;
mod connection;
mod server;
mod stats;

use connection::handle;
use log::{error, info, warn};
use ratum::bitcoin::{OP_RETURN, output_script_size_is_valid};
use ratum::datum::handshake::KeyPairs;
use ratum::datum::messages::ClientConfig;
use ratum::rpc;
use ratum_prime::ledger::{self, Ledger};
use ratum_prime::verify::{PoolPolicy, ReplayGuard};
use server::{
    OpenConnectionGuard, PayoutPolicy, Resolved, Resolver, Server, SharedCoinbaseValue,
    SharedNextBits, SharedTip, resolve_address, watch_node,
};
use std::io;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Where the share ledger lives, as far as the command line settles it.
enum LedgerLocation {
    /// `--ledger <file>`: this file, whatever chain the node is on.
    File(PathBuf),
    /// `--data-dir <dir>` without `--ledger`: `<chain>.redb` inside, named once the node
    /// reports its chain.
    InDir(PathBuf),
    /// Neither: the share window is held in memory only.
    None,
}

/// The `*.redb` files directly inside `dir`, sorted by name.
fn ledger_files_in(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "redb"))
        .collect();
    found.sort();
    Ok(found)
}

/// Print the ledger as `<unix-seconds> <difficulty> <identity> <share-hash>` lines, oldest
/// first, then exit. Exports or audits the ledger; the e2e tests read it this way. Opening
/// takes the ledger's exclusive lock, so the pool must not be running.
/// The column order `<at> <difficulty> <identity> <share-hash>` is read by
/// `tests/e2e/multi_miner.sh` (awk fields 2, 3 and 4) and reconstructed from log lines by
/// `tests/support/pool.rs` `ledger_lines`; a change here changes both.
fn dump_ledger(location: &LedgerLocation) -> io::Result<()> {
    use std::fmt::Write as _;
    let path = match location {
        LedgerLocation::File(p) => p.clone(),
        // The file is named after the node's chain, which is not asked for here (the node
        // need not be running to read a ledger back), so the directory must hold one ledger.
        LedgerLocation::InDir(dir) => match ledger_files_in(dir)?.as_slice() {
            [one] => one.clone(),
            [] => {
                eprintln!("no ledger (*.redb) in {}", dir.display());
                std::process::exit(2);
            }
            many => {
                let names: Vec<String> = many.iter().map(|p| p.display().to_string()).collect();
                eprintln!(
                    "{} holds more than one ledger; give --ledger to choose one of: {}",
                    dir.display(),
                    names.join(", ")
                );
                std::process::exit(2);
            }
        },
        LedgerLocation::None => {
            eprintln!("--dump-ledger needs a ledger: give --ledger or --data-dir");
            std::process::exit(2);
        }
    };
    let (ledger, _) = Ledger::open(&path, u128::MAX, None, None)?;
    let mut out = String::new();
    for share in ledger.dump()? {
        let _ = writeln!(
            out,
            "{} {} {} {}",
            share.at,
            share.difficulty,
            share.identity,
            share.hash.map(hex::encode).unwrap_or_default()
        );
    }
    print!("{out}");
    Ok(())
}

fn load_or_create_keys(path: &Path) -> io::Result<KeyPairs> {
    if path.exists() {
        let text = std::fs::read_to_string(path)?;
        let raw =
            hex::decode(text.trim()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if raw.len() != 160 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "key file must decode to 160 bytes of hex",
            ));
        }
        Ok(KeyPairs {
            sign_pk: raw[0..32].try_into().unwrap(),
            sign_sk: raw[32..96].try_into().unwrap(),
            box_pk: raw[96..128].try_into().unwrap(),
            box_sk: raw[128..160].try_into().unwrap(),
        })
    } else {
        let keys = KeyPairs::generate();
        let mut raw = Vec::with_capacity(160);
        raw.extend_from_slice(&keys.sign_pk);
        raw.extend_from_slice(&keys.sign_sk);
        raw.extend_from_slice(&keys.box_pk);
        raw.extend_from_slice(&keys.box_sk);
        write_private(path, hex::encode(raw).as_bytes())?;
        info!("generated new pool keys at {}", path.display());
        Ok(keys)
    }
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

/// Set up the leveled logger, defaulting to `info`. The README's Logging section covers
/// what each level carries.
///
/// Argument errors keep `eprintln!`: they determine the exit code, so `RUST_LOG=off` must not
/// hide them.
fn init_logging() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
}

fn main() -> io::Result<()> {
    init_logging();
    let loaded = cli::load();
    // After argument parsing, so `--version` and `--help` print only their own output. Every
    // run that reaches this point records which build produced the log that follows.
    info!("ratum-prime {}", ratum::VERSION);
    let c = &loaded.cli;
    let f = loaded.file;

    let listen = cli::resolve_str(c.listen.clone(), f.listen, "0.0.0.0:28915");
    // The read-only stats interface. Unset by default; the interface starts only when this
    // names an address. Bind it to 127.0.0.1 unless it is behind a reverse proxy, since the
    // page is unauthenticated.
    let stats_listen = c.stats_listen.clone().or(f.stats_listen);
    // The host, or host:port, gateways should use to reach the pool, shown on the stats page.
    // Unset falls back to the address the page was reached on, so set this when the public
    // address differs from that (for example the pool is behind NAT or a port-mapping proxy).
    let advertise_address = c.advertise_address.clone().or(f.advertise_address);
    let data_dir = c.data_dir.clone().or(f.data_dir);
    let key_path = c.key.clone().or(f.key);
    let motd = cli::resolve_str(c.motd.clone(), f.motd, "RATUM Prime");
    let min_difficulty = cli::resolve::<u64>(
        c.min_diff.as_deref(),
        f.min_diff,
        16384,
        "--min-diff",
        "a power of two",
        |n| n.is_power_of_two(),
    );
    // Each connection is a gateway served by its own thread, so this bounds threads, file
    // descriptors and memory, and limits a connection flood. It is not a protocol limit. A
    // larger pool raises this together with the process file-descriptor and thread limits.
    let max_connections = cli::resolve::<usize>(
        c.max_connections.as_deref(),
        f.max_connections,
        1024,
        "--max-connections",
        "a positive number",
        |n| *n > 0,
    );
    let mut payout_address = c.payout_address.clone().or(f.payout_address);
    let mut payout_script_hex = c.payout_script.clone().or(f.payout_script);
    let coinbase_tag = cli::resolve_str(c.coinbase_tag.clone(), f.coinbase_tag, "RATUM");
    let prime_id =
        cli::resolve::<u32>(c.prime_id.as_deref(), f.prime_id, 1, "--prime-id", "a number", |_| {
            true
        });
    let ledger_path = c.ledger.clone().or(f.ledger);
    // Each unit keeps SHARES_PER_KEEP_UNIT of the most recent shares; unset keeps every one.
    let ledger_keep = cli::resolve_opt::<usize>(
        c.ledger_keep.as_deref(),
        f.ledger_keep,
        "--ledger-keep",
        "at least 1",
        |n| *n >= 1,
    );
    let window_multiple = cli::resolve::<f64>(
        c.window.as_deref(),
        f.window,
        8.0,
        "--window",
        "a positive number",
        |n| n.is_finite() && *n > 0.0,
    );
    let window_floor = cli::resolve::<u128>(
        c.window_floor.as_deref(),
        f.window_floor,
        1,
        "--window-floor",
        "a sum of share difficulty",
        |_| true,
    )
    .max(1);
    // 546 is Bitcoin Core's dust threshold for a P2PKH output, the highest among the common
    // output types (P2WPKH 294, P2TR 330), so an output at or above it is not dust for any of
    // them. What is withheld goes to the other miners, not to the pool: an identity under the
    // minimum receives no output and its work leaves the denominator.
    let min_payout = cli::resolve::<u64>(
        c.min_payout.as_deref(),
        f.min_payout,
        546,
        "--min-payout",
        "a count of satoshis",
        |_| true,
    );
    // The operator fee in basis points (hundredths of a percent), 0 to 100, so at most 1%. It
    // is deducted from the coinbase value before the split; the gateway pays it to the pool's
    // payout script as the remainder. The default 0 deducts nothing, so the whole value is
    // split among miners.
    let fee_bps = cli::resolve::<u16>(
        c.fee_bps.as_deref(),
        f.fee_bps,
        0,
        "--fee-bps",
        "basis points from 0 to 100 (a fee of at most 1%)",
        |n| *n <= 100,
    );
    let activation_height = cli::resolve_opt::<u32>(
        c.activation_height.as_deref(),
        f.activation_height,
        "--activation-height",
        "a block height",
        |_| true,
    );
    let headline = cli::resolve_str(c.headline.clone(), f.headline, "");
    let rpc_url = c.rpc.clone().or(f.rpc);
    let mut rpc_user = cli::resolve_str(c.rpc_user.clone(), f.rpc_user, "");
    let mut rpc_pass = cli::resolve_str(c.rpc_pass.clone(), f.rpc_pass, "");
    let rpc_cookie = c.rpc_cookie.clone().or(f.rpc_cookie);
    let poll = Duration::from_secs_f64(cli::resolve::<f64>(
        c.poll.as_deref(),
        f.poll,
        0.5,
        "--poll",
        "a positive number of seconds up to 3600",
        |n| n.is_finite() && *n > 0.0 && *n <= 3600.0,
    ));

    // Whether these were on the command line (as opposed to the config file), for the
    // command-line-password warning and the payout override below.
    let rpc_pass_on_argv = c.rpc_pass.is_some();
    let payout_address_on_argv = c.payout_address.is_some();
    let payout_script_on_argv = c.payout_script.is_some();

    let data_dir = data_dir.map(PathBuf::from);
    if let Some(dir) = &data_dir {
        std::fs::create_dir_all(dir)?;
    }
    let key_path = match (key_path, &data_dir) {
        (Some(p), _) => PathBuf::from(p),
        (None, Some(dir)) => dir.join("ratum-prime.key"),
        (None, None) => PathBuf::from("ratum-prime.key"),
    };
    // Where the ledger is: a file named outright, or a data directory in which the file is
    // named after the node's chain (`main.redb`, `testnet4.redb`, ...), known once the node
    // answers.
    let ledger_location = match (ledger_path, &data_dir) {
        (Some(p), _) => LedgerLocation::File(PathBuf::from(p)),
        (None, Some(dir)) => LedgerLocation::InDir(dir.clone()),
        (None, None) => LedgerLocation::None,
    };

    if loaded.cli.dump_ledger {
        return dump_ledger(&ledger_location);
    }

    let pool_keys = load_or_create_keys(&key_path)?;
    info!("pool_pubkey: {}", pool_keys.pubkey_hex());

    let tip: SharedTip = Arc::new(Mutex::new(None));
    let coinbase_value: SharedCoinbaseValue = Arc::new(Mutex::new(None));
    let next_bits: SharedNextBits = Arc::new(Mutex::new(None));
    // A command line is readable by every other process on the machine, so a password
    // given there is not a secret from anyone with a local account.
    if rpc_pass_on_argv {
        warn!(
            "--rpc-pass puts the node's password in this process's command line, where \
             any local user can read it; a configuration file and --rpc-cookie do not"
        );
    }
    if rpc_cookie.is_some() && rpc_pass_on_argv {
        warn!("--rpc-cookie was given as well, and it is the one being used");
    }
    if let Some(path) = &rpc_cookie {
        match std::fs::read_to_string(path) {
            Ok(text) => match text.trim().split_once(':') {
                Some((u, p)) => {
                    rpc_user = u.to_string();
                    rpc_pass = p.to_string();
                }
                None => {
                    eprintln!("{path} is not a cookie file: expected user:password");
                    std::process::exit(2);
                }
            },
            Err(e) => {
                eprintln!("could not read the rpc cookie {path}: {e}");
                std::process::exit(2);
            }
        }
    }

    // A pool without a node cannot resolve a miner's address, so it cannot pay one, and
    // cannot relay the blocks it verifies or detect that a job is stale.
    let Some(url) = &rpc_url else {
        eprintln!(
            "--rpc is required: without a node the pool cannot resolve a miner's address, \
             so every block it finds pays --payout-address and no miner at all"
        );
        std::process::exit(2);
    };
    // With a cookie, give the node client the path so it re-reads on a 401 or 403: bitcoind
    // rewrites the cookie on restart, and otherwise a node restart would leave the pool
    // unable to authenticate until it too was restarted. The early read above still
    // validates the file and exits with status 2 if it is malformed.
    let node = match &rpc_cookie {
        Some(path) => rpc::Client::with_cookie(url, PathBuf::from(path)),
        None => rpc::Client::new(url, &rpc_user, &rpc_pass),
    }
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

    // The two payout options are mutually exclusive, but the command line overrides the file
    // like every other setting: one given on the command line supersedes the other written in
    // the file rather than conflicting with it. Both on the command line, or both only in the
    // file, still reach the refusal below.
    if payout_address.is_some() && payout_script_hex.is_some() {
        match (payout_address_on_argv, payout_script_on_argv) {
            (true, false) => payout_script_hex = None,
            (false, true) => payout_address = None,
            _ => {}
        }
    }

    let payout_script = match (&payout_address, &payout_script_hex) {
        (Some(_), Some(_)) => {
            eprintln!("give --payout-address or --payout-script, not both");
            std::process::exit(2);
        }
        (None, None) => {
            eprintln!(
                "--payout-address (or --payout-script) is required: the gateway reserves a \
                 coinbase output for it on every job, and it receives the value of every \
                 fallback case (an address that does not resolve, a script too long to pay, an \
                 empty window, a split that could not be encoded)"
            );
            std::process::exit(2);
        }
        (None, Some(hex_script)) => match hex::decode(hex_script) {
            // This output takes every fallback payment, so an OP_RETURN one burns them. The
            // DATUM Gateway builds the same output with addr_2_output_script
            // (src/datum_utils.c), which cannot produce one.
            Ok(b) if b.first() == Some(&OP_RETURN) => {
                eprintln!(
                    "--payout-script starts with OP_RETURN, which would burn every fallback \
                     payment rather than pay it"
                );
                std::process::exit(2);
            }
            Ok(b) if !b.is_empty() => b,
            _ => {
                eprintln!("--payout-script must be a non-empty hex script, got {hex_script:?}");
                std::process::exit(2);
            }
        },
        (Some(addr), None) => match resolve_address(&node, addr) {
            Ok(Resolved::Script(b)) => b,
            Ok(Resolved::NoScript) => {
                eprintln!("the node gave no scriptPubKey for {addr:?}");
                std::process::exit(2);
            }
            Ok(Resolved::Invalid) => {
                eprintln!("--payout-address {addr:?} is not an address this node accepts");
                std::process::exit(2);
            }
            Err(e) => {
                eprintln!("could not resolve --payout-address {addr:?}: {e}");
                std::process::exit(2);
            }
        },
    };
    // The gateway copies this script into every stratum job and pays it the coinbase
    // remainder, so unlike an oversized miner output it cannot be left out of the block.
    // While the node enforces the reduced_data rule a block carrying an oversized one is
    // rejected as bad-txns-vout-script-toolarge, and the gateway refuses to serve work for
    // every such block. Both sources need the check: `validateaddress` accepts a future
    // witness version, whose scriptPubKey reaches 42 bytes.
    if !output_script_size_is_valid(&payout_script) {
        let flag = if payout_address.is_some() { "--payout-address" } else { "--payout-script" };
        eprintln!(
            "{flag} gives a {}-byte script, which a block carrying it would be rejected for: \
             a coinbase output script may be at most 34 bytes",
            payout_script.len()
        );
        std::process::exit(2);
    }
    info!("pool payout script: {}", hex::encode(&payout_script));

    // The node's chain names the ledger file and is stamped inside it, so with a ledger to
    // open the node must answer before the pool goes on. Without a ledger the window starts
    // from the floor when the node is unreachable, and is lost on restart in any case.
    let startup_tip = loop {
        match node.tip() {
            Ok(t) => break Some(t),
            Err(e) if matches!(ledger_location, LedgerLocation::None) => {
                warn!(
                    "could not read the node difficulty to size the share window ({e}); \
                     starting from the floor of {window_floor}, so shares recorded before \
                     this restart are credited only as far back as that floor reaches"
                );
                break None;
            }
            Err(e) => {
                warn!(
                    "could not read the node's chain and difficulty ({e}); the ledger is \
                     named after the chain, so retrying in {:.3}s",
                    poll.as_secs_f64()
                );
                std::thread::sleep(poll);
            }
        }
    };
    let chain = startup_tip.map(|t| t.chain);
    let startup_window = match startup_tip {
        Some(t) => ledger::window_for_difficulty(t.difficulty, window_multiple, window_floor),
        None => window_floor,
    };
    {
        let (watcher, shared) = (node.clone(), Arc::clone(&tip));
        let shared_value = Arc::clone(&coinbase_value);
        let shared_bits = Arc::clone(&next_bits);
        std::thread::spawn(move || {
            watch_node(watcher, shared, shared_value, shared_bits, poll, chain)
        });
        info!(
            "watching the node at {url}: waiting on each new block, \
             re-reading the tip at least every {:.3}s",
            poll.as_secs_f64()
        );
    }
    let ledger_path = match (&ledger_location, chain) {
        (LedgerLocation::File(p), _) => Some(p.clone()),
        (LedgerLocation::InDir(dir), Some(rpc::Chain::Other)) => {
            eprintln!(
                "the node reports a chain this pool has no name for, so it cannot name the \
                 ledger in {}; give --ledger a file for it",
                dir.display()
            );
            std::process::exit(2);
        }
        (LedgerLocation::InDir(dir), Some(c)) => Some(dir.join(format!("{}.redb", c.name()))),
        (LedgerLocation::InDir(_), None) => unreachable!("a data directory waits for the chain"),
        (LedgerLocation::None, _) => None,
    };
    let chain_name = chain.map(rpc::Chain::name);

    let ledger = match &ledger_path {
        Some(path) => {
            let (l, read_back) = Ledger::open(path, startup_window, ledger_keep, chain_name)?;
            if read_back.stamped {
                info!(
                    "{} carried no chain stamp and is now stamped {}",
                    path.display(),
                    chain_name.unwrap_or("?")
                );
            }
            if read_back.skipped != 0 {
                warn!("{} unreadable rows in {} were skipped", read_back.skipped, path.display());
            }
            if read_back.truncated {
                warn!(
                    "the share window exceeds the retained ledger in {}: older work is \
                     not credited (raise --ledger-keep to keep it)",
                    path.display()
                );
            }
            info!(
                "share window from {}: {} shares, {} work",
                path.display(),
                l.len(),
                l.total_work()
            );
            match ledger_keep {
                Some(n) => info!(
                    "keeping at most {} of the most recent shares in {}",
                    n as u64 * ledger::SHARES_PER_KEEP_UNIT,
                    path.display()
                ),
                None => info!("every share in {} is kept", path.display()),
            }
            l
        }
        None => {
            warn!("no --ledger file or --data-dir; the share window is lost on restart");
            Ledger::new(startup_window)
        }
    };

    info!(
        "payouts: window {window_multiple}x network difficulty (floor {window_floor}, \
         {startup_window} at startup), minimum {min_payout} sats, \
         operator fee {fee_bps} bps"
    );

    let activation = match (activation_height, headline.is_empty()) {
        (Some(h), false) => {
            info!("activation: height {h}, headline {headline:?}");
            Some((h, headline.clone()))
        }
        (Some(_), true) | (None, false) => {
            eprintln!("--activation-height and --headline must be given together");
            std::process::exit(2);
        }
        (None, true) => None,
    };

    let config = ClientConfig { payout_script, prime_id, coinbase_tag, min_difficulty };
    let config_payload = match config.encode() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("cannot build the client config: {e}");
            std::process::exit(2);
        }
    };
    let mut policy = PoolPolicy::from_config(&config);
    policy.activation = activation;

    // The `ReplayGuard` is in memory only, so without this a restart loses every share it
    // has credited and would credit one of them again if a gateway resent it. The ledger
    // holds their hashes, and the window it has read back is the work still recent enough
    // for a resend to pass the staleness check.
    let replay = ReplayGuard::default();
    let replay = {
        let mut guard = replay;
        let seeded = ledger.hashes().fold(0usize, |n, h| n + usize::from(guard.accept(*h)));
        if seeded != 0 {
            info!("ReplayGuard seeded with {seeded} share hash(es) from the ledger");
        }
        Arc::new(Mutex::new(guard))
    };

    let server = Arc::new(Server {
        pool_keys,
        coinbase_value: Arc::clone(&coinbase_value),
        next_bits,
        motd,
        node,
        tip,
        replay,
        ledger: Mutex::new(ledger),
        resolver: Mutex::new(Resolver::new()),
        payout: PayoutPolicy { min_payout, window_multiple, window_floor, fee_bps },
        policy,
        config_payload,
        open_connections: AtomicUsize::new(0),
        max_connections,
        // The port a gateway connects to, for the stats page to display. Parsed from the
        // configured listen address; the host a gateway uses is the one it reaches the pool on.
        datum_port: listen.rsplit_once(':').and_then(|(_, p)| p.parse().ok()).unwrap_or(0),
        advertise: advertise_address,
    });

    if let Some(addr) = &stats_listen {
        match stats::spawn(Arc::clone(&server), addr) {
            Ok(bound) => info!("stats interface listening on http://{bound}"),
            Err(e) => error!("stats interface could not start on {addr}: {e}"),
        }
    }

    let listener = TcpListener::bind(&listen)?;
    let bound = listener.local_addr().map_or(listen.clone(), |a| a.to_string());
    info!("listening on {bound} (at most {max_connections} connections)");
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
        let conn = Arc::clone(&server);
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
    Ok(())
}
