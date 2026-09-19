//! The ledger commands, which run against the ledger file of a stopped pool and then exit: printing
//! the shares, listing and settling what a block owes, voiding a block's records, and recording
//! amounts owed by hand. Each opens an existing ledger and none creates one.

use crate::cli::{Options, fatal};
use crate::ledger::blocks::{BlockRecords, ConfirmationReading, OwedBlock, Voided};
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
        Some(s) if !s.node_stores_block() => {
            format!(" NOT STORED BY THE NODE as of {}", s.checked_at)
        }
        Some(s) => format!(" NOT ON THE BEST CHAIN as of {}", s.checked_at),
        None => " not yet read from the node".to_string(),
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
                let identity = ratum::bitcoin::address::canonical(id).into_owned().into();
                parsed.push(Payout { identity, sats });
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
    if let Some(owed) = records.owed().iter().find(|o| o.block_hash == hash)
        && let Some(refusal) = settle_refusal(arg, state)
    {
        print_owed(owed, state);
        fatal!("{refusal}");
    }
    print_or_refuse(arg, records.settle_owed(&hash, ratum::unix_now())?, state);
    Ok(())
}

/// Why the owed record of block `arg` may not be settled at its last reading `state`, or none
/// when it may: the reading must exist and place the block on the node's best chain, since a
/// payout settled against a coinbase the chain does not hold is paid from the operator's
/// wallet with nothing received for it.
fn settle_refusal(arg: &str, state: Option<ConfirmationReading>) -> Option<String> {
    let rerun = "Re-run the pool to re-read the block if you believe the chain has changed since.";
    match state {
        None => Some(format!(
            "block {arg} has not been read from the node yet, so the pool does not know whether \
             its coinbase is on the best chain. The pool reads each recorded block's \
             confirmations every five minutes while it runs; run the pool until it has read \
             this one (--settle-block list then prints its confirmations), then settle."
        )),
        Some(s) if !s.node_stores_block() => Some(format!(
            "the node stored no block under {arg} when the pool last read it at {}, so its \
             coinbase pays nobody on that node's chain and the amounts against it are not owed; \
             --void-block {arg} removes the records. {rerun}",
            s.checked_at
        )),
        Some(s) if !s.on_best_chain() => Some(format!(
            "block {arg} was not on the node's best chain when the pool last read it at {} (the \
             node answered {} confirmations), so its coinbase pays nobody and the amounts against \
             it are not owed; --void-block {arg} removes the records. {rerun}",
            s.checked_at, s.confirmations
        )),
        Some(_) => None,
    }
}

/// Removes the block's record, its owed record and its confirmation reading, whichever exist,
/// and prints what was removed; refuses a hash under which there is neither record.
fn void_block(location: &LedgerLocation, arg: &str) -> io::Result<()> {
    let mut records = open_records(location, "--void-block")?;
    let hash = block_hash_arg("--void-block", arg, "");
    let state = records.confirmations(&hash);
    let Voided { block, owed } = records.void_block(&hash)?;
    if block.is_none() && owed.is_none() {
        fatal!(
            "no block and no owed record under {arg} in the ledger; --settle-block list prints \
             the owed records"
        );
    }
    if let Some(b) = &block {
        println!(
            "removed block {arg} at height {} found {} from the block history{}",
            b.height,
            b.found_at,
            confirmations_text(state)
        );
    }
    if let Some(o) = &owed {
        println!("removed its owed record:");
        print_owed(o, state);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(confirmations: i64) -> Option<ConfirmationReading> {
        Some(ConfirmationReading { checked_at: 1_750_000_000, confirmations })
    }

    #[test]
    fn a_block_is_settled_only_after_a_reading_places_it_on_the_best_chain() {
        let unread = settle_refusal("ab", None).expect("a block never read is refused");
        assert!(unread.contains("has not been read from the node yet"), "{unread}");
        assert!(unread.contains("run the pool"), "{unread}");
        let orphan = settle_refusal("ab", read(-1)).expect("a block off the best chain");
        assert!(orphan.contains("-1 confirmations") && orphan.contains("--void-block ab"));
        let gone = settle_refusal("ab", read(ConfirmationReading::NOT_STORED)).expect("not stored");
        assert!(gone.contains("stored no block under ab") && gone.contains("--void-block ab"));
        assert_eq!(settle_refusal("ab", read(0)), None, "the tip itself");
        assert_eq!(settle_refusal("ab", read(100)), None);
    }

    #[test]
    fn the_printed_state_names_every_kind_of_reading() {
        assert_eq!(confirmations_text(read(3)), " 3 confirmations");
        assert!(confirmations_text(read(-1)).contains("NOT ON THE BEST CHAIN"));
        assert!(confirmations_text(read(ConfirmationReading::NOT_STORED)).contains("NOT STORED"));
        assert_eq!(confirmations_text(None), " not yet read from the node");
    }

    #[test]
    fn an_owed_entry_names_the_identity_a_share_of_that_address_is_credited_to() {
        let entries = owed_entries(&[
            "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4=5".to_string(),
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 = 7".to_string(),
        ]);
        assert_eq!(&*entries[0].identity, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert_eq!(&*entries[1].identity, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
        assert_eq!((entries[0].sats, entries[1].sats), (5, 7));
    }

    #[test]
    fn a_ledger_command_on_a_missing_file_is_refused_naming_the_path_and_creates_nothing() {
        let scratch = crate::fixtures::Scratch::new("admin-missing");
        let dir = scratch.dir().to_path_buf();
        let location = LedgerLocation::InDir(dir.clone());
        for (flag, run) in [
            ("--settle-block", settle_block as fn(&LedgerLocation, &str) -> io::Result<()>),
            ("--void-block", void_block),
        ] {
            let e = run(&location, "list").expect_err(flag);
            assert_eq!(e.kind(), io::ErrorKind::NotFound, "{flag}");
            assert!(e.to_string().contains(&dir.display().to_string()), "{flag}: {e}");
            assert!(e.to_string().contains(flag), "{flag}: {e}");
        }
        let e = record_owed(&location, "list", &[]).expect_err("--record-owed");
        assert!(e.to_string().contains("--record-owed"), "{e}");
        let e = dump_ledger(&location).expect_err("--dump-ledger");
        assert!(e.to_string().contains("--dump-ledger"), "{e}");
        assert!(std::fs::read_dir(&dir).unwrap().next().is_none(), "no command created a file");
    }

    #[test]
    fn voiding_an_orphan_with_no_owed_record_removes_its_block_record() {
        use crate::fixtures::found;
        use crate::ledger::{Ledger, WindowRule, open_share_ledger, split::SplitPolicy};
        let scratch = crate::fixtures::Scratch::new("admin-void");
        let path = scratch.join("regtest.redb");
        let orphan = found(1, 16);
        {
            let ledger = Ledger::new(WindowRule::fixed(u128::MAX), SplitPolicy::default());
            let (_, mut records) =
                open_share_ledger(Some(&path), None, Some("regtest"), ledger).unwrap();
            records.record_block(orphan.clone()).unwrap();
            records.record_block(found(2, 32)).unwrap();
            let reading = ConfirmationReading { checked_at: 5, confirmations: -1 };
            records.record_confirmations(orphan.block_hash, reading).unwrap();
        }
        let location = LedgerLocation::InDir(scratch.dir().to_path_buf());
        void_block(&location, &hex::encode(orphan.block_hash)).unwrap();
        let records = BlockRecords::open_file(&path).unwrap();
        assert_eq!(records.blocks(), &[found(2, 32)], "only the orphan was removed");
        assert_eq!(records.confirmations(&orphan.block_hash), None);
    }
}
