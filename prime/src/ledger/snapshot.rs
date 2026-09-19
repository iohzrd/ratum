//! A copy of the ledger file written while the pool records shares: one read transaction's view
//! of every table, copied into a new file that is verified to open and then renamed into place.

use super::blocks::{BLOCKS, CHAIN_STATE, OWED};
use super::db::{DbResult as _, create_in_file, open_database, write};
use super::store::{META, RETIRED_BY_HASH, SHARES};
use redb::{
    Database, Key, MultimapTableHandle as _, ReadTransaction, ReadableDatabase, ReadableTable,
    ReadableTableMetadata, TableDefinition, TableHandle as _, Value, WriteTransaction,
};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

/// The rows a snapshot holds, per table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SnapshotCounts {
    pub shares: u64,
    pub meta: u64,
    pub blocks: u64,
    pub owed: u64,
    pub readings: u64,
}

impl SnapshotCounts {
    /// The count for the table `name`; none for a table this build does not have.
    fn of(&mut self, name: &str) -> Option<&mut u64> {
        Some(match name {
            n if n == SHARES.name() => &mut self.shares,
            n if n == META.name() => &mut self.meta,
            n if n == BLOCKS.name() => &mut self.blocks,
            n if n == OWED.name() => &mut self.owed,
            n if n == CHAIN_STATE.name() => &mut self.readings,
            _ => return None,
        })
    }
}

impl fmt::Display for SnapshotCounts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} shares, {} blocks, {} owed records, {} confirmation readings",
            self.shares, self.blocks, self.owed, self.readings
        )
    }
}

fn unknown_table(ledger: &Path, name: &str) -> io::Error {
    io::Error::other(format!(
        "{} holds a table this build of ratum-prime cannot copy ({name}), so no snapshot is \
         written",
        ledger.display()
    ))
}

/// Why `target` may not hold a snapshot of the ledger at `ledger`, or none when it may: any
/// path in the ledger's own directory, which holds the pool's files (the live ledger, its key
/// and settings; a `.redb` beside the ledger is read as a second ledger and refused). A
/// subdirectory is allowed.
pub fn snapshot_refusal(target: &Path, ledger: &Path) -> Option<String> {
    let dir_of = |p: &Path| {
        let dir = p.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
        dir.canonicalize().ok()
    };
    let (Some(target_dir), Some(ledger_dir)) = (dir_of(target), dir_of(ledger)) else {
        return None;
    };
    if target_dir != ledger_dir {
        return None;
    }
    Some(if target.file_name() == ledger.file_name() {
        format!("{} is the live ledger", target.display())
    } else {
        format!(
            "{} is in the data directory {}, which holds the pool's own files; write the \
             snapshot to another directory",
            target.display(),
            ledger_dir.display()
        )
    })
}

/// Writes the snapshot of `db`, the ledger at `ledger`, to `target`: every table as one read
/// transaction sees it, into `<target>.tmp`, which is opened again and its row counts checked
/// before it is renamed to `target`. The pool's writes proceed meanwhile and are not in the
/// copy. Returns the rows copied.
pub fn write_snapshot(db: &Database, ledger: &Path, target: &Path) -> io::Result<SnapshotCounts> {
    let tmp = temporary_name(target);
    if let Err(e) = std::fs::remove_file(&tmp)
        && e.kind() != io::ErrorKind::NotFound
    {
        return Err(named(&tmp, "cannot remove", e));
    }
    let file = std::fs::File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|e| named(&tmp, "cannot create", e))?;
    let written = copy_into(db, ledger, file).and_then(|copied| {
        let read_back = counts_in(&open_database(&tmp)?)?;
        if read_back != copied {
            return Err(io::Error::other(format!(
                "{} holds {read_back} after being written with {copied}",
                tmp.display()
            )));
        }
        std::fs::rename(&tmp, target).map_err(|e| named(target, "cannot rename the copy to", e))?;
        if let Some(dir) = target.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::File::open(dir)?.sync_all()?;
        }
        Ok(copied)
    });
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

fn temporary_name(target: &Path) -> PathBuf {
    let mut tmp = target.as_os_str().to_owned();
    tmp.push(".tmp");
    PathBuf::from(tmp)
}

fn named(path: &Path, what: &str, e: io::Error) -> io::Error {
    io::Error::new(e.kind(), format!("{what} {}: {e}", path.display()))
}

/// Copies every table of `db` into a new database in `file`, in one write transaction of the
/// copy committed durably, and closes the copy.
fn copy_into(db: &Database, ledger: &Path, file: std::fs::File) -> io::Result<SnapshotCounts> {
    let copy = create_in_file(file)?;
    let r = db.begin_read().db()?;
    if let Some(multimap) = r.list_multimap_tables().db()?.next() {
        return Err(unknown_table(ledger, multimap.name()));
    }
    let tables: Vec<String> = r.list_tables().db()?.map(|t| t.name().to_string()).collect();
    write(&copy, |w| {
        let mut counts = SnapshotCounts::default();
        for name in &tables {
            let rows = match name.as_str() {
                n if n == SHARES.name() => copy_table(&r, w, SHARES)?,
                n if n == META.name() => copy_table(&r, w, META)?,
                n if n == BLOCKS.name() => copy_table(&r, w, BLOCKS)?,
                n if n == OWED.name() => copy_table(&r, w, OWED)?,
                n if n == CHAIN_STATE.name() => copy_table(&r, w, CHAIN_STATE)?,
                // Deleted by `Store::open`; held by a ledger no pool has opened since.
                n if n == RETIRED_BY_HASH.name() => continue,
                other => return Err(unknown_table(ledger, other)),
            };
            *counts.of(name).expect("matched above") = rows;
        }
        Ok(counts)
    })
}

fn copy_table<K: Key + 'static, V: Value + 'static>(
    r: &ReadTransaction,
    w: &WriteTransaction,
    table: TableDefinition<'static, K, V>,
) -> io::Result<u64> {
    let source = r.open_table(table).db()?;
    let mut copy = w.open_table(table).db()?;
    let mut rows = 0;
    for entry in source.iter().db()? {
        let (key, value) = entry.db()?;
        copy.insert(key.value(), value.value()).db()?;
        rows += 1;
    }
    Ok(rows)
}

/// The rows of every table of `db`; an error for a table this build does not have.
fn counts_in(db: &Database) -> io::Result<SnapshotCounts> {
    let r = db.begin_read().db()?;
    let mut counts = SnapshotCounts::default();
    for handle in r.list_tables().db()? {
        let name = handle.name().to_string();
        let rows = r.open_untyped_table(handle).db()?.len().db()?;
        match counts.of(&name) {
            Some(count) => *count = rows,
            None => return Err(io::Error::other(format!("unknown table {name}"))),
        }
    }
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{Scratch, found, hash, owed, share};
    use crate::ledger::blocks::{BlockRecords, ConfirmationReading};
    use crate::ledger::db::create_database;
    use crate::ledger::split::SplitPolicy;
    use crate::ledger::{Ledger, WindowRule, dump_file, open_share_ledger};

    fn ledger_with_shares(path: &Path, shares: u64) -> (Ledger, BlockRecords) {
        let ledger = Ledger::new(WindowRule::fixed(u128::MAX), SplitPolicy::default());
        let (mut ledger, mut records) =
            open_share_ledger(Some(path), None, Some("regtest"), ledger).unwrap();
        for i in 0..shares {
            ledger.record(share(1_000 + i, "alice", 16, hash(i), "tag")).unwrap();
        }
        records.record_block(found(1, 16)).unwrap();
        records.record_owed(owed(1, None)).unwrap();
        let reading = ConfirmationReading { checked_at: 5, confirmations: 3 };
        records.record_confirmations(found(1, 16).block_hash, reading).unwrap();
        (ledger, records)
    }

    #[test]
    fn a_snapshot_holds_every_table_and_opens_on_its_own() {
        let scratch = Scratch::new("snapshot");
        let live = scratch.join("regtest.redb");
        let (mut ledger, records) = ledger_with_shares(&live, 5);
        let (db, _) = ledger.file().unwrap();
        std::fs::create_dir_all(scratch.join("backups")).unwrap();
        let target = scratch.join("backups/regtest.redb");
        let counts = write_snapshot(&db, &live, &target).unwrap();
        assert_eq!(
            counts,
            SnapshotCounts { shares: 5, meta: 2, blocks: 1, owed: 1, readings: 1 },
            "the chain stamp and the cumulative work are the meta rows"
        );
        assert!(!temporary_name(&target).exists(), "the temporary file was renamed away");
        ledger.record(share(2_000, "alice", 16, hash(99), "")).unwrap();
        drop(records);
        drop(ledger);

        let copy = BlockRecords::open_file(&target).unwrap();
        assert_eq!(copy.blocks(), &[found(1, 16)]);
        assert_eq!(copy.owed(), &[owed(1, None)]);
        assert_eq!(
            copy.confirmations(&found(1, 16).block_hash),
            Some(ConfirmationReading { checked_at: 5, confirmations: 3 })
        );
        drop(copy);
        let mut dumped = 0;
        dump_file(&target, |_| {
            dumped += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(dumped, 5, "the share recorded after the snapshot is not in it");
        assert_eq!(
            counts.to_string(),
            "5 shares, 1 blocks, 1 owed records, 1 confirmation readings"
        );
    }

    #[test]
    fn a_snapshot_replaces_a_previous_one_and_a_leftover_temporary_file() {
        let scratch = Scratch::new("snapshot-replace");
        let live = scratch.join("regtest.redb");
        let (ledger, _records) = ledger_with_shares(&live, 2);
        let (db, _) = ledger.file().unwrap();
        let target = scratch.join("copy");
        std::fs::write(&target, b"an older snapshot").unwrap();
        std::fs::write(temporary_name(&target), b"left by an interrupted snapshot").unwrap();
        assert_eq!(write_snapshot(&db, &live, &target).unwrap().shares, 2);
        assert_eq!(counts_in(&open_database(&target).unwrap()).unwrap().shares, 2);
        assert!(!temporary_name(&target).exists());
    }

    #[test]
    fn the_live_ledger_and_every_other_path_in_its_directory_are_refused_as_targets() {
        let scratch = Scratch::new("snapshot-refusal");
        let live = scratch.join("regtest.redb");
        let (ledger, _records) = ledger_with_shares(&live, 1);
        let (db, _) = ledger.file().unwrap();
        let same = snapshot_refusal(&scratch.join("regtest.redb"), &live).expect("the ledger");
        assert!(same.contains("is the live ledger"), "{same}");
        for name in ["backup.redb", "backup.bak", "ratum-prime.key", "ratum.toml"] {
            let beside = snapshot_refusal(&scratch.join(name), &live).expect(name);
            assert!(beside.contains("holds the pool's own files"), "{beside}");
        }
        std::fs::create_dir_all(scratch.join("backups")).unwrap();
        let below = scratch.join("backups/regtest.redb");
        assert_eq!(snapshot_refusal(&below, &live), None);
        assert_eq!(snapshot_refusal(Path::new("/nowhere/regtest.redb"), &live), None);
        assert_eq!(write_snapshot(&db, &live, &below).unwrap().shares, 1);
        let e = write_snapshot(&db, &live, Path::new("/nowhere/regtest.redb")).unwrap_err();
        assert!(e.to_string().contains("/nowhere/regtest.redb.tmp"), "{e}");
    }

    /// A ledger last written before the hash index was retired holds it until a pool opens the
    /// file; a command on the stopped pool opens it as is, and the snapshot leaves the index out.
    #[test]
    fn a_ledger_holding_the_retired_hash_index_snapshots_without_it() {
        let scratch = Scratch::new("snapshot-retired");
        let live = scratch.join("regtest.redb");
        drop(ledger_with_shares(&live, 3));
        {
            let db = create_database(&live).unwrap();
            write(&db, |w| {
                w.open_table(RETIRED_BY_HASH).db()?.insert([7u8; 32].as_slice(), 0).db()?;
                Ok(())
            })
            .unwrap();
        }
        let stopped = open_database(&live).unwrap();
        std::fs::create_dir_all(scratch.join("backups")).unwrap();
        let target = scratch.join("backups/regtest.redb");
        assert_eq!(write_snapshot(&stopped, &live, &target).unwrap().shares, 3);
        drop(stopped);
        let copy = counts_in(&open_database(&target).unwrap()).expect("only tables this build has");
        assert_eq!(copy.shares, 3);
    }
}
