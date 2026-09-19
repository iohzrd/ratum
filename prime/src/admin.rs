//! The ledger commands: listing and settling what a block owes, voiding a block's records,
//! recording amounts owed by hand, printing the shares, and writing a snapshot of the ledger
//! file. Each runs in the pool that owns the data directory, over its control socket
//! (`control`), or against the ledger file directly when no pool answers or `--offline` is given.
//! None creates a ledger.

use crate::cli::{Options, USAGE_EXIT};
use crate::control;
use crate::ledger::blocks::{BlockRecords, ConfirmationReading, OwedBlock, Voided};
use crate::ledger::split::Payout;
use crate::ledger::{self, LedgerLocation, Share};
use redb::Database;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Write as _};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;

/// A ledger command as its flags give it. Serialized as the control socket's request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "kebab-case")]
pub enum Command {
    /// `--settle-block <hash>`, or `--settle-block list`.
    SettleBlock {
        arg: String,
    },
    VoidBlock {
        arg: String,
    },
    /// `--record-owed <hash>` with each `--owed identity=sats`.
    RecordOwed {
        arg: String,
        owed: Vec<String>,
    },
    DumpLedger,
    /// `--snapshot <path>`, made absolute by the client since the pool writes it.
    Snapshot {
        path: PathBuf,
    },
}

impl Command {
    /// The command the options name, or none when they name no ledger command.
    pub fn from_options(o: &Options) -> Option<Self> {
        if o.dump_ledger {
            return Some(Self::DumpLedger);
        }
        if let Some(arg) = &o.settle_block {
            return Some(Self::SettleBlock { arg: arg.clone() });
        }
        if let Some(arg) = &o.void_block {
            return Some(Self::VoidBlock { arg: arg.clone() });
        }
        if let Some(arg) = &o.record_owed {
            return Some(Self::RecordOwed { arg: arg.clone(), owed: o.owed.clone() });
        }
        let path = o.snapshot.as_ref()?;
        let path = std::path::absolute(path).unwrap_or_else(|_| PathBuf::from(path));
        Some(Self::Snapshot { path })
    }

    pub fn flag(&self) -> &'static str {
        match self {
            Self::SettleBlock { .. } => "--settle-block",
            Self::VoidBlock { .. } => "--void-block",
            Self::RecordOwed { .. } => "--record-owed",
            Self::DumpLedger => "--dump-ledger",
            Self::Snapshot { .. } => "--snapshot",
        }
    }
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.flag())?;
        match self {
            Self::SettleBlock { arg } | Self::VoidBlock { arg } => write!(f, " {arg}"),
            Self::RecordOwed { arg, owed } => {
                write!(f, " {arg}")?;
                owed.iter().try_for_each(|entry| write!(f, " --owed {entry}"))
            }
            Self::DumpLedger => Ok(()),
            Self::Snapshot { path } => write!(f, " {}", path.display()),
        }
    }
}

/// Why a command did not complete.
#[derive(Debug)]
pub enum Failure {
    /// Refused as given; the process exits `USAGE_EXIT` after the text is written to stderr.
    Usage(String),
    /// The ledger could not be read or written; the process exits 1.
    Io(io::Error),
}

impl From<io::Error> for Failure {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl Failure {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) => USAGE_EXIT,
            Self::Io(_) => 1,
        }
    }

    pub fn message(&self) -> String {
        match self {
            Self::Usage(text) => text.clone(),
            Self::Io(e) => e.to_string(),
        }
    }
}

/// What a command reads and writes: the block records under whatever lock guards them, and
/// the ledger file for the commands that read it through their own transaction.
pub trait LedgerAccess {
    /// Runs `f` on the records, which no socket or file I/O happens under.
    fn with_records<T>(&mut self, f: impl FnOnce(&mut BlockRecords) -> T) -> io::Result<T>;

    /// The ledger file's database and path.
    fn database(&mut self) -> io::Result<(Arc<Database>, PathBuf)>;
}

/// The ledger file of a stopped pool: opened by each command, never created.
struct FileLedger<'a> {
    location: &'a LedgerLocation,
    flag: &'static str,
}

impl LedgerAccess for FileLedger<'_> {
    fn with_records<T>(&mut self, f: impl FnOnce(&mut BlockRecords) -> T) -> io::Result<T> {
        let mut records = BlockRecords::open_file(&self.location.existing_file(self.flag)?)?;
        Ok(f(&mut records))
    }

    fn database(&mut self) -> io::Result<(Arc<Database>, PathBuf)> {
        let path = self.location.existing_file(self.flag)?;
        Ok((Arc::new(ledger::open_existing(&path)?), path))
    }
}

/// Runs `command` at `now`, writing what it prints to `out`. The records are read and
/// written inside `access.with_records`; the text goes to `out` after that returns, so a
/// slow `out` never holds the records.
pub fn execute(
    command: &Command,
    access: &mut impl LedgerAccess,
    now: u64,
    out: &mut dyn Write,
) -> Result<(), Failure> {
    match command {
        Command::DumpLedger => {
            let (db, _) = access.database()?;
            ledger::dump(&db, |share| write_share(out, &share))?;
            Ok(())
        }
        Command::Snapshot { path } => {
            let (db, live) = access.database()?;
            if let Some(why) = ledger::snapshot_refusal(path, &live) {
                return Err(Failure::Usage(format!("--snapshot: {why}")));
            }
            let counts = ledger::write_snapshot(&db, &live, path)?;
            writeln!(
                out,
                "snapshot of {} written to {}: {counts}",
                live.display(),
                path.display()
            )?;
            Ok(())
        }
        _ => {
            let mut text = String::new();
            let result = access.with_records(|records| match command {
                Command::SettleBlock { arg } => settle_block(records, arg, now, &mut text),
                Command::VoidBlock { arg } => void_block(records, arg, &mut text),
                Command::RecordOwed { arg, owed } => record_owed(records, arg, owed, &mut text),
                Command::DumpLedger | Command::Snapshot { .. } => unreachable!("matched above"),
            })?;
            out.write_all(text.as_bytes())?;
            result
        }
    }
}

/// One share as `--dump-ledger` prints it: time, difficulty, identity, hash, secondary tag.
pub fn write_share(out: &mut dyn Write, s: &Share) -> io::Result<()> {
    writeln!(
        out,
        "{} {} {} {} {}",
        s.accepted_at,
        s.difficulty,
        s.identity,
        hex::encode(s.block_hash),
        s.tag_secondary
    )
}

/// Runs the command the options name, if any: through the pool at the data directory's
/// control socket, or on the ledger file when no pool answers or `--offline` is given.
pub fn run_command(options: &Options, location: &LedgerLocation) -> Option<io::Result<()>> {
    let Some(command) = Command::from_options(options) else {
        if options.offline {
            crate::cli::fatal!(
                "--offline applies to a ledger command (--settle-block, --void-block, \
                 --record-owed, --dump-ledger, --snapshot); none was given"
            );
        }
        return None;
    };
    Some(run(&command, options.offline, location))
}

/// An error reaching the pool or the ledger file is one line on stderr and exit code 1, as a
/// failure the pool answers is.
fn run(command: &Command, offline: bool, location: &LedgerLocation) -> io::Result<()> {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    let mut err = io::stderr().lock();
    let code = match run_to(command, offline, location, &mut out, &mut err) {
        Ok(code) => code,
        Err(e) => {
            writeln!(err, "{e}")?;
            1
        }
    };
    out.flush()?;
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

/// Sends `command` to the pool at the data directory's control socket, or runs it on the
/// ledger file when there is no pool to answer (no socket, or one no pool listens on) or
/// `offline` is set, and says on `err` which. What the command prints goes to `out`; the
/// result is the exit code, after the text of a refusal went to `err`.
pub fn run_to(
    command: &Command,
    offline: bool,
    location: &LedgerLocation,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> io::Result<i32> {
    if let LedgerLocation::InDir(dir) = location {
        let socket = dir.join(control::SOCKET_NAME);
        if offline {
            writeln!(err, "--offline: opening the ledger in {} directly", dir.display())?;
        } else {
            match control::connect(&socket) {
                Ok(stream) => {
                    writeln!(err, "executed by the pool at {}", socket.display())?;
                    return control::send(stream, command, out, err);
                }
                Err(control::ConnectError::NoPool(why)) => writeln!(
                    err,
                    "no pool at {} ({why}); opening the ledger in {} directly",
                    socket.display(),
                    dir.display()
                )?,
                Err(control::ConnectError::Failed(e)) => return Err(e),
            }
        }
    }
    run_offline(command, location, ratum::unix_now(), out, err)
}

/// Runs `command` on the ledger file at `now`: what it prints goes to `out`, and the result
/// is the exit code, after the text of a refusal went to `err`.
pub fn run_offline(
    command: &Command,
    location: &LedgerLocation,
    now: u64,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> io::Result<i32> {
    let mut access = FileLedger { location, flag: command.flag() };
    match execute(command, &mut access, now, out) {
        Ok(()) => Ok(0),
        Err(Failure::Usage(message)) => {
            writeln!(err, "{message}")?;
            Ok(USAGE_EXIT)
        }
        Err(Failure::Io(e)) => Err(e),
    }
}

fn block_hash_arg(flag: &str, arg: &str, also: &str) -> Result<[u8; 32], Failure> {
    hex::decode(arg).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| {
        Failure::Usage(format!(
            "{flag} takes the block hash the pool logged (64 hex digits){also}, got {arg:?}"
        ))
    })
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

fn write_owed(out: &mut String, o: &OwedBlock, state: Option<ConfirmationReading>) {
    let status = match o.settled_at {
        Some(at) => format!("settled at {at}"),
        None => "unsettled".to_string(),
    };
    let _ = writeln!(
        out,
        "height {} block {} found {} total {} sats {status}{}",
        o.height,
        hex::encode(o.block_hash),
        o.found_at,
        o.total(),
        confirmations_text(state)
    );
    for Payout { identity, sats } in &o.entries {
        let _ = writeln!(out, "  {identity} {sats}");
    }
}

fn owed_entries(entries: &[String]) -> Result<Vec<Payout>, Failure> {
    let mut parsed: Vec<Payout> = Vec::with_capacity(entries.len());
    for entry in entries {
        let split = entry.split_once('=').map(|(id, sats)| (id.trim(), sats.trim().parse::<u64>()));
        match split {
            Some((id, Ok(sats))) if !id.is_empty() && sats > 0 => {
                let identity = ratum::bitcoin::address::canonical(id).into_owned().into();
                parsed.push(Payout { identity, sats });
            }
            _ => {
                return Err(Failure::Usage(format!(
                    "--owed takes identity=sats with a positive whole number of sats, got {entry:?}"
                )));
            }
        }
    }
    if parsed.is_empty() {
        return Err(Failure::Usage(
            "--record-owed needs at least one --owed identity=sats".to_string(),
        ));
    }
    Ok(parsed)
}

fn record_owed(
    records: &mut BlockRecords,
    arg: &str,
    entries: &[String],
    out: &mut String,
) -> Result<(), Failure> {
    let hash = block_hash_arg("--record-owed", arg, "")?;
    let Some(block) = records.blocks().iter().find(|b| b.block_hash == hash).cloned() else {
        return Err(Failure::Usage(format!(
            "no block under {arg} in the ledger's block history; the pool records every block \
             it accepted there"
        )));
    };
    if let Some(existing) = records.owed().iter().find(|o| o.block_hash == hash) {
        write_owed(out, existing, records.confirmations(&hash));
        return Err(Failure::Usage(format!(
            "block {arg} already has an owed record; --void-block removes it first:"
        )));
    }
    let owed = OwedBlock {
        found_at: block.found_at,
        height: block.height,
        block_hash: hash,
        settled_at: None,
        entries: owed_entries(entries)?,
    };
    let total = owed.total();
    if total > block.paid_to_pool {
        return Err(Failure::Usage(format!(
            "the entries total {total} sats, more than the {} sats the block's coinbase paid to \
             the pool's payout script (a figure that includes the operator fee, which is not \
             owed)",
            block.paid_to_pool
        )));
    }
    records.record_owed(owed.clone())?;
    write_owed(out, &owed, records.confirmations(&hash));
    Ok(())
}

fn settle_block(
    records: &mut BlockRecords,
    arg: &str,
    now: u64,
    out: &mut String,
) -> Result<(), Failure> {
    if arg == "list" {
        if records.owed().is_empty() {
            out.push_str("no owed blocks\n");
        }
        for o in records.owed() {
            write_owed(out, o, records.confirmations(&o.block_hash));
        }
        return Ok(());
    }
    let hash = block_hash_arg("--settle-block", arg, " or 'list'")?;
    let state = records.confirmations(&hash);
    if let Some(owed) = records.owed().iter().find(|o| o.block_hash == hash)
        && let Some(refusal) = settle_refusal(arg, state)
    {
        write_owed(out, owed, state);
        return Err(Failure::Usage(refusal));
    }
    match records.settle_owed(&hash, now)? {
        Some(owed) => {
            write_owed(out, &owed, state);
            Ok(())
        }
        None => Err(Failure::Usage(format!(
            "no owed block under {arg}; --settle-block list prints them"
        ))),
    }
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
fn void_block(records: &mut BlockRecords, arg: &str, out: &mut String) -> Result<(), Failure> {
    let hash = block_hash_arg("--void-block", arg, "")?;
    let state = records.confirmations(&hash);
    let Voided { block, owed } = records.void_block(&hash)?;
    if block.is_none() && owed.is_none() {
        return Err(Failure::Usage(format!(
            "no block and no owed record under {arg} in the ledger; --settle-block list prints \
             the owed records"
        )));
    }
    if let Some(b) = &block {
        let _ = writeln!(
            out,
            "removed block {arg} at height {} found {} from the block history{}",
            b.height,
            b.found_at,
            confirmations_text(state)
        );
    }
    if let Some(o) = &owed {
        out.push_str("removed its owed record:\n");
        write_owed(out, o, state);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(confirmations: i64) -> Option<ConfirmationReading> {
        Some(ConfirmationReading { checked_at: 1_750_000_000, confirmations })
    }

    /// `run_offline` at a fixed time, with what it wrote to stdout and stderr.
    pub(crate) fn offline(
        command: &Command,
        location: &LedgerLocation,
        now: u64,
    ) -> io::Result<(i32, String, String)> {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run_offline(command, location, now, &mut out, &mut err)?;
        Ok((code, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap()))
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
        ])
        .unwrap();
        assert_eq!(&*entries[0].identity, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert_eq!(&*entries[1].identity, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
        assert_eq!((entries[0].sats, entries[1].sats), (5, 7));
        let e = owed_entries(&["alice=0".to_string()]).unwrap_err();
        assert!(matches!(e, Failure::Usage(ref m) if m.contains("positive")), "{e:?}");
        assert!(matches!(owed_entries(&[]).unwrap_err(), Failure::Usage(_)));
    }

    #[test]
    fn the_options_name_one_command_and_a_relative_snapshot_path_is_made_absolute() {
        assert_eq!(Command::from_options(&Options::default()), None);
        let o = Options {
            settle_block: Some("list".into()),
            offline: true,
            snapshot: Some("backup".into()),
            ..Options::default()
        };
        assert_eq!(Command::from_options(&o), Some(Command::SettleBlock { arg: "list".into() }));
        let o = Options { snapshot: Some("backups/main".into()), ..Options::default() };
        let Some(Command::Snapshot { path }) = Command::from_options(&o) else { panic!() };
        assert!(path.is_absolute(), "{}", path.display());
        assert!(path.ends_with("backups/main"), "{}", path.display());
        let o = Options {
            record_owed: Some("ab".into()),
            owed: vec!["alice=1".into(), "bob=2".into()],
            ..Options::default()
        };
        let command = Command::from_options(&o).unwrap();
        assert_eq!(command.to_string(), "--record-owed ab --owed alice=1 --owed bob=2");
        assert_eq!(Command::DumpLedger.to_string(), "--dump-ledger");
    }

    #[test]
    fn a_ledger_command_on_a_missing_file_is_refused_naming_the_path_and_creates_nothing() {
        let scratch = crate::fixtures::Scratch::new("admin-missing");
        let dir = scratch.dir().to_path_buf();
        let location = LedgerLocation::InDir(dir.clone());
        for command in [
            Command::SettleBlock { arg: "list".into() },
            Command::VoidBlock { arg: "list".into() },
            Command::RecordOwed { arg: "list".into(), owed: vec![] },
            Command::DumpLedger,
            Command::Snapshot { path: dir.join("copy") },
        ] {
            let flag = command.flag();
            let e = offline(&command, &location, 1).expect_err(flag);
            assert_eq!(e.kind(), io::ErrorKind::NotFound, "{flag}");
            assert!(e.to_string().contains(&dir.display().to_string()), "{flag}: {e}");
            assert!(e.to_string().contains(flag), "{flag}: {e}");
        }
        let e = offline(&Command::DumpLedger, &LedgerLocation::MemoryOnly, 1).unwrap_err();
        assert!(e.to_string().contains("give --data-dir"), "{e}");
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
        let void = Command::VoidBlock { arg: hex::encode(orphan.block_hash) };
        let (code, out, err) = offline(&void, &location, 1).unwrap();
        assert_eq!((code, err.as_str()), (0, ""));
        assert!(out.starts_with("removed block "), "{out}");
        assert!(out.contains("NOT ON THE BEST CHAIN as of 5"), "{out}");
        let records = BlockRecords::open_file(&path).unwrap();
        assert_eq!(records.blocks(), &[found(2, 32)], "only the orphan was removed");
        assert_eq!(records.confirmations(&orphan.block_hash), None);
        drop(records);
        let (code, out, err) = offline(&void, &location, 1).unwrap();
        assert_eq!((code, out.as_str()), (USAGE_EXIT, ""));
        assert!(err.starts_with("no block and no owed record under "), "{err}");
    }
}
