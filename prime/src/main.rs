mod abw;
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
    NodeView, OpenConnectionGuard, PayoutPolicy, Resolved, Resolver, Server, resolve_address,
    watch_node,
};
use std::io;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const DUST_THRESHOLD_P2PKH: u64 = 546;

const MAX_FEE_BPS: u16 = 100;

const DEFAULT_POLL_SECS: f64 = 0.5;

const DEFAULT_MIN_DIFFICULTY: u64 = 16384;

const DEFAULT_MAX_CONNECTIONS: usize = 1024;

enum LedgerLocation {
    File(PathBuf),
    InDir(PathBuf),
    None,
}

fn ledger_files_in(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "redb"))
        .collect();
    found.sort();
    Ok(found)
}

fn ledger_path_for(location: &LedgerLocation, flag: &str) -> io::Result<PathBuf> {
    Ok(match location {
        LedgerLocation::File(p) => p.clone(),
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
            eprintln!("{flag} needs a ledger: give --ledger or --data-dir");
            std::process::exit(2);
        }
    })
}

fn open_ledger(location: &LedgerLocation, flag: &str) -> io::Result<Ledger> {
    let path = ledger_path_for(location, flag)?;
    Ledger::open(&path, u128::MAX, None, None).map(|(ledger, _)| ledger)
}

fn block_hash_arg(flag: &str, arg: &str, also: &str) -> [u8; 32] {
    let Some(hash) = hex::decode(arg).ok().and_then(|v| v.try_into().ok()) else {
        eprintln!("{flag} takes the block hash the pool logged (64 hex digits){also}, got {arg:?}");
        std::process::exit(2);
    };
    hash
}

fn print_or_refuse(arg: &str, record: Option<ledger::OwedBlock>) -> io::Result<()> {
    let Some(owed) = record else {
        eprintln!("no owed block under {arg}; --settle-block list prints them");
        std::process::exit(2);
    };
    print_owed(&owed);
    Ok(())
}

fn dump_ledger(location: &LedgerLocation) -> io::Result<()> {
    use std::fmt::Write as _;
    let ledger = open_ledger(location, "--dump-ledger")?;
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

fn print_owed(o: &ledger::OwedBlock) {
    let status = match o.settled_at {
        Some(at) => format!("settled at {at}"),
        None => "unsettled".to_string(),
    };
    println!(
        "height {} block {} found {} total {} sats {status}",
        o.height,
        hex::encode(o.block_hash),
        o.at,
        o.total
    );
    for (identity, sats) in &o.entries {
        println!("  {identity} {sats}");
    }
}

fn record_owed(location: &LedgerLocation, arg: &str, entries: &[String]) -> io::Result<()> {
    let mut ledger = open_ledger(location, "--record-owed")?;
    let hash = block_hash_arg("--record-owed", arg, "");
    let Some(block) = ledger.blocks().iter().find(|b| b.block_hash == hash).cloned() else {
        eprintln!(
            "no block under {arg} in the ledger's block history; the pool records every block \
             it accepted there"
        );
        std::process::exit(2);
    };
    if let Some(existing) = ledger.owed().iter().find(|o| o.block_hash == hash) {
        eprintln!("block {arg} already has an owed record; --void-block removes it first:");
        print_owed(existing);
        std::process::exit(2);
    }
    let mut parsed: Vec<(String, u64)> = Vec::with_capacity(entries.len());
    for entry in entries {
        let split = entry.split_once('=').map(|(id, sats)| (id.trim(), sats.trim().parse::<u64>()));
        match split {
            Some((id, Ok(sats))) if !id.is_empty() && sats > 0 => {
                parsed.push((id.to_string(), sats));
            }
            _ => {
                eprintln!(
                    "--owed takes identity=sats with a positive whole number of sats, got \
                     {entry:?}"
                );
                std::process::exit(2);
            }
        }
    }
    if parsed.is_empty() {
        eprintln!("--record-owed needs at least one --owed identity=sats");
        std::process::exit(2);
    }
    let total: u64 = parsed.iter().map(|(_, sats)| *sats).sum();
    if total > block.paid_to_pool {
        eprintln!(
            "the entries total {total} sats, more than the {} sats the block's coinbase paid to \
             the pool's payout script (a figure that includes the operator fee, which is not \
             owed)",
            block.paid_to_pool
        );
        std::process::exit(2);
    }
    let owed = ledger::OwedBlock {
        at: block.at,
        height: block.height,
        block_hash: hash,
        total,
        settled_at: None,
        entries: parsed,
    };
    ledger.record_owed(owed.clone())?;
    print_owed(&owed);
    Ok(())
}

fn settle_block(location: &LedgerLocation, arg: &str) -> io::Result<()> {
    let mut ledger = open_ledger(location, "--settle-block")?;
    if arg == "list" {
        if ledger.owed().is_empty() {
            println!("no owed blocks");
        }
        for o in ledger.owed() {
            print_owed(o);
        }
        return Ok(());
    }
    let hash = block_hash_arg("--settle-block", arg, " or 'list'");
    print_or_refuse(arg, ledger.settle_owed(&hash, ratum::unix_now())?)
}

fn void_block(location: &LedgerLocation, arg: &str) -> io::Result<()> {
    let mut ledger = open_ledger(location, "--void-block")?;
    let hash = block_hash_arg("--void-block", arg, "");
    print_or_refuse(arg, ledger.void_owed(&hash)?)
}

fn load_or_create_keys(path: &Path) -> io::Result<KeyPairs> {
    if path.exists() {
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
    } else {
        let keys = KeyPairs::generate();
        write_private(path, hex::encode(keys.to_bytes()).as_bytes())?;
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

fn init_logging() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
}

struct Settings {
    listen: String,
    stats_listen: Option<String>,
    advertise_address: Option<String>,
    public_gateway: Option<String>,
    data_dir: Option<String>,
    key_path: Option<String>,
    motd: String,
    allowed_agents: Vec<String>,
    require_v3: bool,
    abw_reveal_after: u64,
    min_difficulty: u64,
    max_connections: usize,
    payout_address: Option<String>,
    payout_script_hex: Option<String>,
    coinbase_tag: String,
    prime_id: u32,
    ledger_path: Option<String>,
    ledger_keep: Option<usize>,
    window_multiple: f64,
    window_floor: u128,
    min_payout: u64,
    fee_bps: u16,
    rpc_url: Option<String>,
    rpc_user: String,
    rpc_pass: String,
    rpc_cookie: Option<String>,
    poll: Duration,
    require_split: bool,
    rpc_pass_on_argv: bool,
    payout_address_on_argv: bool,
    payout_script_on_argv: bool,
}

fn settings(c: &cli::Cli, f: ratum_prime::config::Config) -> Settings {
    let reveal_range = abw::REVEAL_AFTER_SECS_RANGE;
    let reveal_must_be = format!("{} to {} (seconds)", reveal_range.start(), reveal_range.end());
    let max_poll_secs = ratum::SECS_PER_HOUR as f64;
    Settings {
        listen: cli::resolve_str(c.listen.clone(), f.listen, "0.0.0.0:28915"),
        stats_listen: c.stats_listen.clone().or(f.stats_listen),
        advertise_address: c.advertise_address.clone().or(f.advertise_address),
        public_gateway: c.public_gateway.clone().or(f.public_gateway).map(|u| {
            if u.starts_with("http://") || u.starts_with("https://") {
                u
            } else {
                format!("https://{u}")
            }
        }),
        data_dir: c.data_dir.clone().or(f.data_dir),
        key_path: c.key.clone().or(f.key),
        motd: cli::resolve_str(c.motd.clone(), f.motd, "RATUM Prime"),
        allowed_agents: cli::resolve_str(c.allow_agent.clone(), f.allow_agent, "")
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .collect(),
        require_v3: cli::resolve::<bool>(
            c.require_v3.as_deref(),
            f.require_v3,
            false,
            "--require-v3",
            "true or false",
            |_| true,
        ),
        abw_reveal_after: cli::resolve::<u64>(
            c.abw_reveal_after.as_deref(),
            f.abw_reveal_after,
            abw::DEFAULT_REVEAL_AFTER.as_secs(),
            "--abw-reveal-after",
            &reveal_must_be,
            |n| reveal_range.contains(n),
        ),
        min_difficulty: cli::resolve::<u64>(
            c.min_diff.as_deref(),
            f.min_diff,
            DEFAULT_MIN_DIFFICULTY,
            "--min-diff",
            "a power of two",
            |n| n.is_power_of_two(),
        ),
        max_connections: cli::resolve::<usize>(
            c.max_connections.as_deref(),
            f.max_connections,
            DEFAULT_MAX_CONNECTIONS,
            "--max-connections",
            "a positive number",
            |n| *n > 0,
        ),
        payout_address: c.payout_address.clone().or(f.payout_address),
        payout_script_hex: c.payout_script.clone().or(f.payout_script),
        coinbase_tag: cli::resolve_str(c.coinbase_tag.clone(), f.coinbase_tag, "RATUM"),
        prime_id: cli::resolve::<u32>(
            c.prime_id.as_deref(),
            f.prime_id,
            1,
            "--prime-id",
            "a positive number",
            |n| *n > 0,
        ),
        ledger_path: c.ledger.clone().or(f.ledger),
        ledger_keep: cli::resolve_opt::<usize>(
            c.ledger_keep.as_deref(),
            f.ledger_keep,
            "--ledger-keep",
            "at least 1",
            |n| *n >= 1,
        ),
        window_multiple: cli::resolve::<f64>(
            c.window.as_deref(),
            f.window,
            8.0,
            "--window",
            "a positive number",
            |n| n.is_finite() && *n > 0.0,
        ),
        window_floor: cli::resolve::<u128>(
            c.window_floor.as_deref(),
            f.window_floor,
            1,
            "--window-floor",
            "a sum of share difficulty",
            |_| true,
        )
        .max(1),
        min_payout: cli::resolve::<u64>(
            c.min_payout.as_deref(),
            f.min_payout,
            DUST_THRESHOLD_P2PKH,
            "--min-payout",
            "a count of satoshis",
            |_| true,
        ),
        fee_bps: cli::resolve::<u16>(
            c.fee_bps.as_deref(),
            f.fee_bps,
            0,
            "--fee-bps",
            &format!(
                "basis points from 0 to {MAX_FEE_BPS} (a fee of at most {}%)",
                f64::from(MAX_FEE_BPS) / 100.0
            ),
            |n| *n <= MAX_FEE_BPS,
        ),
        rpc_url: c.rpc.clone().or(f.rpc),
        rpc_user: cli::resolve_str(c.rpc_user.clone(), f.rpc_user, ""),
        rpc_pass: cli::resolve_str(c.rpc_pass.clone(), f.rpc_pass, ""),
        rpc_cookie: c.rpc_cookie.clone().or(f.rpc_cookie),
        poll: Duration::from_secs_f64(cli::resolve::<f64>(
            c.poll.as_deref(),
            f.poll,
            DEFAULT_POLL_SECS,
            "--poll",
            &format!("a positive number of seconds up to {max_poll_secs:.0}"),
            |n| n.is_finite() && *n > 0.0 && *n <= max_poll_secs,
        )),
        require_split: cli::resolve::<bool>(
            c.require_split.as_deref(),
            f.require_split,
            true,
            "--require-split",
            "true or false",
            |_| true,
        ),
        rpc_pass_on_argv: c.rpc_pass.is_some(),
        payout_address_on_argv: c.payout_address.is_some(),
        payout_script_on_argv: c.payout_script.is_some(),
    }
}

fn connect_node(
    rpc_url: &Option<String>,
    rpc_user: &str,
    rpc_pass: &str,
    rpc_cookie: &Option<String>,
    rpc_pass_on_argv: bool,
) -> io::Result<rpc::Client> {
    if rpc_pass_on_argv {
        warn!(
            "--rpc-pass puts the node's password in this process's command line, where \
             any local user can read it; a configuration file and --rpc-cookie do not"
        );
    }
    if rpc_cookie.is_some() && rpc_pass_on_argv {
        warn!("--rpc-cookie was given as well, and it is the one being used");
    }
    if let Some(path) = rpc_cookie {
        match std::fs::read_to_string(path) {
            Ok(text) if text.trim().split_once(':').is_some() => {}
            Ok(_) => {
                eprintln!("{path} is not a cookie file: expected user:password");
                std::process::exit(2);
            }
            Err(e) => {
                eprintln!("could not read the rpc cookie {path}: {e}");
                std::process::exit(2);
            }
        }
    }
    let Some(url) = rpc_url else {
        eprintln!(
            "--rpc is required: without a node the pool cannot resolve a miner's address, \
             so every block it finds pays --payout-address and no miner at all"
        );
        std::process::exit(2);
    };
    match rpc_cookie {
        Some(path) => rpc::Client::with_cookie(url, PathBuf::from(path)),
        None => rpc::Client::new(url, rpc_user, rpc_pass),
    }
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
}

fn payout_script(
    node: &rpc::Client,
    mut payout_address: Option<String>,
    mut payout_script_hex: Option<String>,
    payout_address_on_argv: bool,
    payout_script_on_argv: bool,
) -> Vec<u8> {
    if payout_address.is_some() && payout_script_hex.is_some() {
        match (payout_address_on_argv, payout_script_on_argv) {
            (true, false) => payout_script_hex = None,
            (false, true) => payout_address = None,
            _ => {}
        }
    }

    let script = match (&payout_address, &payout_script_hex) {
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
        (Some(addr), None) => match resolve_address(node, addr) {
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
    if !output_script_size_is_valid(&script) {
        let flag = if payout_address.is_some() { "--payout-address" } else { "--payout-script" };
        eprintln!(
            "{flag} gives a {}-byte script, which a block carrying it would be rejected for: \
             a coinbase output script may be at most {} bytes",
            script.len(),
            ratum::bitcoin::MAX_OUTPUT_SCRIPT_SIZE
        );
        std::process::exit(2);
    }
    script
}

fn startup_chain_and_window(
    node: &rpc::Client,
    location: &LedgerLocation,
    poll: Duration,
    window_multiple: f64,
    window_floor: u128,
) -> (Option<rpc::Chain>, u128) {
    let tip = loop {
        match node.tip() {
            Ok(t) => break Some(t),
            Err(e) if matches!(location, LedgerLocation::None) => {
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
    let window = match tip {
        Some(t) => ledger::window_for_difficulty(t.difficulty, window_multiple, window_floor),
        None => window_floor,
    };
    (tip.map(|t| t.chain), window)
}

fn ledger_file(location: &LedgerLocation, chain: Option<rpc::Chain>) -> Option<PathBuf> {
    match (location, chain) {
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
    }
}

fn open_share_ledger(
    ledger_path: Option<&PathBuf>,
    startup_window: u128,
    ledger_keep: Option<usize>,
    chain_name: Option<&str>,
) -> io::Result<Ledger> {
    let Some(path) = ledger_path else {
        warn!("no --ledger file or --data-dir; the share window is lost on restart");
        return Ok(Ledger::new(startup_window));
    };
    let (ledger, read_back) = Ledger::open(path, startup_window, ledger_keep, chain_name)?;
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
            "the share window exceeds the retained ledger in {}: older work is not credited \
             (raise --ledger-keep to keep it)",
            path.display()
        );
    }
    info!(
        "share window from {}: {} shares, {} work",
        path.display(),
        ledger.len(),
        ledger.total_work()
    );
    match ledger_keep {
        Some(n) => info!(
            "keeping at most {} of the most recent shares in {}",
            n as u64 * ledger::SHARES_PER_KEEP_UNIT,
            path.display()
        ),
        None => info!("every share in {} is kept", path.display()),
    }
    Ok(ledger)
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

    let Settings {
        listen,
        stats_listen,
        advertise_address,
        public_gateway,
        data_dir,
        key_path,
        motd,
        allowed_agents,
        require_v3,
        abw_reveal_after,
        min_difficulty,
        max_connections,
        payout_address,
        payout_script_hex,
        coinbase_tag,
        prime_id,
        ledger_path,
        ledger_keep,
        window_multiple,
        window_floor,
        min_payout,
        fee_bps,
        rpc_url,
        rpc_user,
        rpc_pass,
        rpc_cookie,
        poll,
        require_split,
        rpc_pass_on_argv,
        payout_address_on_argv,
        payout_script_on_argv,
    } = settings(&loaded.cli, loaded.file);

    let data_dir = data_dir.map(PathBuf::from);
    if let Some(dir) = &data_dir {
        std::fs::create_dir_all(dir)?;
    }
    let key_path = match (key_path, &data_dir) {
        (Some(p), _) => PathBuf::from(p),
        (None, Some(dir)) => dir.join("ratum-prime.key"),
        (None, None) => PathBuf::from("ratum-prime.key"),
    };
    let ledger_location = match (ledger_path, &data_dir) {
        (Some(p), _) => LedgerLocation::File(PathBuf::from(p)),
        (None, Some(dir)) => LedgerLocation::InDir(dir.clone()),
        (None, None) => LedgerLocation::None,
    };

    if loaded.cli.dump_ledger {
        return dump_ledger(&ledger_location);
    }
    if let Some(arg) = &loaded.cli.settle_block {
        return settle_block(&ledger_location, arg);
    }
    if let Some(arg) = &loaded.cli.void_block {
        return void_block(&ledger_location, arg);
    }
    if let Some(arg) = &loaded.cli.record_owed {
        return record_owed(&ledger_location, arg, &loaded.cli.owed);
    }

    let pool_keys = load_or_create_keys(&key_path)?;
    info!("pool_pubkey: {}", pool_keys.pubkey_hex());

    let node = connect_node(&rpc_url, &rpc_user, &rpc_pass, &rpc_cookie, rpc_pass_on_argv)?;
    let payout_script = payout_script(
        &node,
        payout_address,
        payout_script_hex,
        payout_address_on_argv,
        payout_script_on_argv,
    );
    info!("pool payout script: {}", hex::encode(&payout_script));

    let (chain, startup_window) =
        startup_chain_and_window(&node, &ledger_location, poll, window_multiple, window_floor);
    let node_view = Arc::new(NodeView::new());
    {
        let (watcher, view) = (node.clone(), Arc::clone(&node_view));
        std::thread::spawn(move || watch_node(watcher, view, poll, chain));
        info!(
            "watching the node at {}: waiting on each new block, \
             re-reading the tip at least every {:.3}s",
            node.url(),
            poll.as_secs_f64()
        );
    }
    let ledger_path = ledger_file(&ledger_location, chain);
    let chain_name = chain.map(rpc::Chain::name);

    let ledger = open_share_ledger(ledger_path.as_ref(), startup_window, ledger_keep, chain_name)?;

    info!(
        "payouts: window {window_multiple}x network difficulty (floor {window_floor}, \
         {startup_window} at startup), minimum {min_payout} sats, \
         operator fee {fee_bps} bps"
    );

    let config = ClientConfig { payout_script, prime_id, coinbase_tag, min_difficulty };
    let config_payload = match config.encode() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("cannot build the client config: {e}");
            std::process::exit(2);
        }
    };
    let mut policy = PoolPolicy::from_config(&config);
    policy.require_split = require_split;
    if !policy.require_split {
        info!(
            "--require-split=false: a coinbase paying only the pool script is accepted from any job"
        );
    }

    let replay = {
        let mut guard = ReplayGuard::default();
        let seeded = ledger.hashes().fold(0usize, |n, h| n + usize::from(guard.accept(*h)));
        if seeded != 0 {
            info!("ReplayGuard seeded with {seeded} share hash(es) from the ledger");
        }
        Arc::new(Mutex::new(guard))
    };

    if !allowed_agents.is_empty() {
        info!(
            "gateway user agents restricted to the prefixes {allowed_agents:?}; others are refused at hello"
        );
    }
    if require_v3 {
        info!(
            "version 3 protocol required: a hello without the DRS extension is refused, so \
             every connection is under an anti-block-withholding assignment"
        );
    }
    let server = Arc::new(Server {
        pool_keys,
        node_view,
        motd,
        allowed_agents,
        require_v3,
        sessions: Mutex::new(server::SessionStore::default()),
        abw_reveal_after: std::time::Duration::from_secs(abw_reveal_after),
        node,
        replay,
        ledger: Mutex::new(ledger),
        resolver: Mutex::new(Resolver::new()),
        payout: PayoutPolicy { min_payout, window_multiple, window_floor, fee_bps },
        policy,
        config_payload,
        open_connections: AtomicUsize::new(0),
        max_connections,
        datum_port: listen.rsplit_once(':').and_then(|(_, p)| p.parse().ok()).unwrap_or(0),
        advertise: advertise_address,
        public_gateway,
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
    accept_connections(listener, &server);
    Ok(())
}
