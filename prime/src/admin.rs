//! The ledger commands, which run against the ledger file of a stopped pool and then exit: printing
//! the shares, listing and settling what a block owes, voiding a record, and recording amounts owed
//! by hand.

use crate::cli::{Options, fatal};
use crate::ledger::blocks::{BlockRecords, ConfirmationReading, OwedBlock};
use crate::ledger::split::Payout;
use crate::ledger::{self, LedgerLocation};
use std::io;

fn open_records(location: &LedgerLocation, flag: &str) -> io::Result<BlockRecords> {
    BlockRecords::open_file(&location.existing_file(flag)?)
}

pub fn run_command(options: &Options, location: &LedgerLocation) -> Option<io::Result<()>> {
    if options.dump_ledger {
        return Some(dump_ledger(location));
    }
    if let Some(arg) = &options.settle_block {
        return Some(settle_block(location, arg));
    }
    if let Some(arg) = &options.void_block {
        return Some(void_block(location, arg));
    }
    if let Some(arg) = &options.record_owed {
        return Some(record_owed(location, arg, &options.owed));
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

fn print_or_refuse(arg: &str, record: Option<OwedBlock>, state: Option<ConfirmationReading>) {
    let Some(owed) = record else {
        fatal!("no owed block under {arg}; --settle-block list prints them")
    };
    print_owed(&owed, state);
}

fn confirmations_text(state: Option<ConfirmationReading>) -> String {
    match state {
        Some(s) if s.on_best_chain() => format!(" {} confirmations", s.confirmations),
        Some(s) => format!(" NOT ON THE BEST CHAIN as of {}", s.checked_at),
        None => String::new(),
    }
}

fn print_owed(o: &OwedBlock, state: Option<ConfirmationReading>) {
    let status = match o.settled_at {
        Some(at) => format!("settled at {at}"),
        None => "unsettled".to_string(),
    };
    println!(
        "height {} block {} found {} total {} sats {status}{}",
        o.height,
        hex::encode(o.block_hash),
        o.found_at,
        o.total(),
        confirmations_text(state)
    );
    for Payout { identity, sats } in &o.entries {
        println!("  {identity} {sats}");
    }
}

/// Writes each share as it is read, so the ledger is never held in memory whole.
fn dump_ledger(location: &LedgerLocation) -> io::Result<()> {
    use std::io::Write as _;
    let path = location.existing_file("--dump-ledger")?;
    let mut out = io::BufWriter::new(io::stdout().lock());
    ledger::dump_file(&path, |share| {
        writeln!(
            out,
            "{} {} {} {} {}",
            share.accepted_at,
            share.difficulty,
            share.identity,
            hex::encode(share.block_hash),
            share.tag_secondary
        )
    })?;
    out.flush()
}

fn owed_entries(entries: &[String]) -> Vec<Payout> {
    let mut parsed: Vec<Payout> = Vec::with_capacity(entries.len());
    for entry in entries {
        let split = entry.split_once('=').map(|(id, sats)| (id.trim(), sats.trim().parse::<u64>()));
        match split {
            Some((id, Ok(sats))) if !id.is_empty() && sats > 0 => {
                parsed.push(Payout { identity: id.to_string(), sats });
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
    let mut records = open_records(location, "--record-owed")?;
    let hash = block_hash_arg("--record-owed", arg, "");
    let Some(block) = records.blocks().iter().find(|b| b.block_hash == hash).cloned() else {
        fatal!(
            "no block under {arg} in the ledger's block history; the pool records every block \
             it accepted there"
        )
    };
    if let Some(existing) = records.owed().iter().find(|o| o.block_hash == hash) {
        eprintln!("block {arg} already has an owed record; --void-block removes it first:");
        print_owed(existing, records.confirmations(&hash));
        std::process::exit(crate::cli::USAGE_EXIT);
    }
    let owed = OwedBlock {
        found_at: block.found_at,
        height: block.height,
        block_hash: hash,
        settled_at: None,
        entries: owed_entries(entries),
    };
    let total = owed.total();
    if total > block.paid_to_pool {
        fatal!(
            "the entries total {total} sats, more than the {} sats the block's coinbase paid to \
             the pool's payout script (a figure that includes the operator fee, which is not \
             owed)",
            block.paid_to_pool
        );
    }
    records.record_owed(owed.clone())?;
    print_owed(&owed, records.confirmations(&hash));
    Ok(())
}

fn settle_block(location: &LedgerLocation, arg: &str) -> io::Result<()> {
    let mut records = open_records(location, "--settle-block")?;
    if arg == "list" {
        if records.owed().is_empty() {
            println!("no owed blocks");
        }
        for o in records.owed() {
            print_owed(o, records.confirmations(&o.block_hash));
        }
        return Ok(());
    }
    let hash = block_hash_arg("--settle-block", arg, " or 'list'");
    let state = records.confirmations(&hash);
    if let Some(s) = state.filter(|s| !s.on_best_chain()) {
        if let Some(owed) = records.owed().iter().find(|o| o.block_hash == hash) {
            print_owed(owed, state);
        }
        fatal!(
            "block {arg} was not on the node's best chain when the pool last read it at {} (the \
             node answered {} confirmations), so its coinbase pays nobody and the amounts against \
             it are not owed; --void-block {arg} removes the record. Re-run the pool to re-read \
             the block if you believe the chain has changed since.",
            s.checked_at,
            s.confirmations
        );
    }
    print_or_refuse(arg, records.settle_owed(&hash, ratum::unix_now())?, state);
    Ok(())
}

fn void_block(location: &LedgerLocation, arg: &str) -> io::Result<()> {
    let mut records = open_records(location, "--void-block")?;
    let hash = block_hash_arg("--void-block", arg, "");
    let state = records.confirmations(&hash);
    print_or_refuse(arg, records.void_owed(&hash)?, state);
    Ok(())
}
