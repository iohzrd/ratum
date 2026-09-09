use crate::cli::{Cli, fatal};
use log::{info, warn};
use ratum::rpc;
use ratum_prime::ledger::{self, Ledger};
use std::io;
use std::path::{Path, PathBuf};

pub(crate) enum LedgerLocation {
    File(PathBuf),
    InDir(PathBuf),
    None,
}

impl LedgerLocation {
    pub(crate) fn new(ledger_path: Option<String>, data_dir: Option<&PathBuf>) -> Self {
        match (ledger_path, data_dir) {
            (Some(p), _) => Self::File(PathBuf::from(p)),
            (None, Some(dir)) => Self::InDir(dir.clone()),
            (None, None) => Self::None,
        }
    }

    pub(crate) fn file_for(&self, chain: Option<rpc::Chain>) -> Option<PathBuf> {
        match (self, chain) {
            (Self::File(p), _) => Some(p.clone()),
            (Self::InDir(dir), Some(rpc::Chain::Other)) => fatal!(
                "the node reports a chain this pool has no name for, so it cannot name the \
                 ledger in {}; give --ledger a file for it",
                dir.display()
            ),
            (Self::InDir(dir), Some(c)) => Some(dir.join(format!("{}.redb", c.name()))),
            (Self::InDir(_), None) => {
                unreachable!("a data directory waits for the chain")
            }
            (Self::None, _) => None,
        }
    }

    fn existing_file(&self, flag: &str) -> io::Result<PathBuf> {
        Ok(match self {
            Self::File(p) => p.clone(),
            Self::InDir(dir) => match ledger_files_in(dir)?.as_slice() {
                [one] => one.clone(),
                [] => fatal!("no ledger (*.redb) in {}", dir.display()),
                many => {
                    let names: Vec<String> = many.iter().map(|p| p.display().to_string()).collect();
                    fatal!(
                        "{} holds more than one ledger; give --ledger to choose one of: {}",
                        dir.display(),
                        names.join(", ")
                    )
                }
            },
            Self::None => fatal!("{flag} needs a ledger: give --ledger or --data-dir"),
        })
    }

    fn open(&self, flag: &str) -> io::Result<Ledger> {
        let path = self.existing_file(flag)?;
        Ledger::open(&path, u128::MAX, None, None).map(|(ledger, _)| ledger)
    }
}

fn ledger_files_in(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "redb"))
        .collect();
    found.sort();
    Ok(found)
}

pub(crate) fn run_command(cli: &Cli, location: &LedgerLocation) -> Option<io::Result<()>> {
    if cli.dump_ledger {
        return Some(dump_ledger(location));
    }
    if let Some(arg) = &cli.settle_block {
        return Some(settle_block(location, arg));
    }
    if let Some(arg) = &cli.void_block {
        return Some(void_block(location, arg));
    }
    if let Some(arg) = &cli.record_owed {
        return Some(record_owed(location, arg, &cli.owed));
    }
    None
}

fn block_hash_arg(flag: &str, arg: &str, also: &str) -> [u8; 32] {
    match hex::decode(arg).ok().and_then(|v| v.try_into().ok()) {
        Some(hash) => hash,
        None => {
            fatal!("{flag} takes the block hash the pool logged (64 hex digits){also}, got {arg:?}")
        }
    }
}

fn print_or_refuse(arg: &str, record: Option<ledger::OwedBlock>) {
    let Some(owed) = record else {
        fatal!("no owed block under {arg}; --settle-block list prints them")
    };
    print_owed(&owed);
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

fn dump_ledger(location: &LedgerLocation) -> io::Result<()> {
    use std::fmt::Write as _;
    let ledger = location.open("--dump-ledger")?;
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

fn owed_entries(entries: &[String]) -> Vec<(String, u64)> {
    let mut parsed: Vec<(String, u64)> = Vec::with_capacity(entries.len());
    for entry in entries {
        let split = entry.split_once('=').map(|(id, sats)| (id.trim(), sats.trim().parse::<u64>()));
        match split {
            Some((id, Ok(sats))) if !id.is_empty() && sats > 0 => {
                parsed.push((id.to_string(), sats));
            }
            _ => fatal!(
                "--owed takes identity=sats with a positive whole number of sats, got {entry:?}"
            ),
        }
    }
    if parsed.is_empty() {
        fatal!("--record-owed needs at least one --owed identity=sats");
    }
    parsed
}

fn record_owed(location: &LedgerLocation, arg: &str, entries: &[String]) -> io::Result<()> {
    let mut ledger = location.open("--record-owed")?;
    let hash = block_hash_arg("--record-owed", arg, "");
    let Some(block) = ledger.blocks().iter().find(|b| b.block_hash == hash).cloned() else {
        fatal!(
            "no block under {arg} in the ledger's block history; the pool records every block \
             it accepted there"
        )
    };
    if let Some(existing) = ledger.owed().iter().find(|o| o.block_hash == hash) {
        eprintln!("block {arg} already has an owed record; --void-block removes it first:");
        print_owed(existing);
        std::process::exit(crate::cli::USAGE_EXIT);
    }
    let entries = owed_entries(entries);
    let total: u64 = entries.iter().map(|(_, sats)| *sats).sum();
    if total > block.paid_to_pool {
        fatal!(
            "the entries total {total} sats, more than the {} sats the block's coinbase paid to \
             the pool's payout script (a figure that includes the operator fee, which is not \
             owed)",
            block.paid_to_pool
        );
    }
    let owed = ledger::OwedBlock {
        at: block.at,
        height: block.height,
        block_hash: hash,
        total,
        settled_at: None,
        entries,
    };
    ledger.record_owed(owed.clone())?;
    print_owed(&owed);
    Ok(())
}

fn settle_block(location: &LedgerLocation, arg: &str) -> io::Result<()> {
    let mut ledger = location.open("--settle-block")?;
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
    print_or_refuse(arg, ledger.settle_owed(&hash, ratum::unix_now())?);
    Ok(())
}

fn void_block(location: &LedgerLocation, arg: &str) -> io::Result<()> {
    let mut ledger = location.open("--void-block")?;
    let hash = block_hash_arg("--void-block", arg, "");
    print_or_refuse(arg, ledger.void_owed(&hash)?);
    Ok(())
}

pub(crate) fn open_share_ledger(
    path: Option<&PathBuf>,
    startup_window: u128,
    keep: Option<usize>,
    chain_name: Option<&str>,
) -> io::Result<Ledger> {
    let Some(path) = path else {
        warn!("no --ledger file or --data-dir; the share window is lost on restart");
        return Ok(Ledger::new(startup_window));
    };
    let (ledger, read_back) = Ledger::open(path, startup_window, keep, chain_name)?;
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
    match keep {
        Some(n) => info!(
            "keeping at most {} of the most recent shares in {}",
            n as u64 * ledger::SHARES_PER_KEEP_UNIT,
            path.display()
        ),
        None => info!("every share in {} is kept", path.display()),
    }
    Ok(ledger)
}
