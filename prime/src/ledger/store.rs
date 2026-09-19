//! The share rows on disk, each under a sequence number, and the metadata beside them: the chain
//! the ledger serves and the running total of credited work.

use super::db::{
    DbResult as _, NAME_SEPARATOR, create_database, open_database, split_at_separator, write,
};
use super::{ReadBack, Share};
use bytes::BufMut as _;
use ratum::bitcoin::HASH_SIZE;
use ratum::reader::ByteReader;
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use std::io;
use std::path::Path;
use std::sync::Arc;

const SHARES: TableDefinition<u64, &[u8]> = TableDefinition::new("shares");
/// A hash index earlier versions kept beside `SHARES`; deleted when a ledger is opened, since
/// `accounting::claim` refuses a duplicate share before it reaches the store.
const RETIRED_BY_HASH: TableDefinition<&[u8], u64> = TableDefinition::new("by_hash");

const META: TableDefinition<&str, &str> = TableDefinition::new("meta");
const META_CHAIN: &str = "chain";
const META_CUMULATIVE_WORK: &str = "cumulative_work";

const SHARE_PREFIX_LEN: usize = 2 * size_of::<u64>() + HASH_SIZE;
/// The most rows one retention call removes. It runs under the ledger lock as each share is
/// recorded, so a surplus of millions of rows (retention set or lowered on a large ledger) is
/// removed over successive shares rather than in one transaction that holds every share
/// waiting and a vector of every surplus row's key.
const MAX_RETAINED_PER_CALL: u64 = 4096;

fn pack(share: &Share) -> Vec<u8> {
    let mut v =
        Vec::with_capacity(SHARE_PREFIX_LEN + 1 + share.identity.len() + share.tag_secondary.len());
    v.put_u64_le(share.accepted_at);
    v.put_u64_le(share.difficulty);
    v.put_slice(&share.block_hash);
    v.put_slice(share.identity.as_bytes());
    v.put_u8(NAME_SEPARATOR);
    v.put_slice(share.tag_secondary.as_bytes());
    v
}

fn unpack(bytes: &[u8]) -> Option<Share> {
    let mut c = ByteReader::new(bytes);
    let accepted_at = c.u64("accepted_at").ok()?;
    let difficulty = c.u64("difficulty").ok()?;
    let hash: [u8; HASH_SIZE] = c.arr("hash").ok()?;
    let (identity, tag) = split_at_separator(c.rest());
    Some(Share {
        accepted_at,
        identity: String::from_utf8_lossy(identity).into_owned(),
        difficulty,
        block_hash: hash,
        tag_secondary: String::from_utf8_lossy(tag).into_owned(),
    })
}

/// The fixed fields at the head of a packed row, without the identity and tag after them, so a
/// scan that needs only these allocates nothing. A row `unpack` cannot read fails here too.
struct RowHead {
    accepted_at: u64,
    difficulty: u64,
    block_hash: [u8; HASH_SIZE],
}

fn unpack_head(bytes: &[u8]) -> Option<RowHead> {
    let mut c = ByteReader::new(bytes);
    let accepted_at = c.u64("accepted_at").ok()?;
    let difficulty = c.u64("difficulty").ok()?;
    let block_hash: [u8; HASH_SIZE] = c.arr("hash").ok()?;
    Some(RowHead { accepted_at, difficulty, block_hash })
}

/// What `Store::read_window` passes on: the number of shares it will read, then each one.
pub(super) enum WindowRow {
    Count(usize),
    Share(Share),
}

pub(super) struct Store {
    db: Arc<Database>,
    next_seq: u64,
    retain_bound: Option<u64>,
    /// The counter as the store held it when it was opened; the ledger carries it on.
    pub(super) cumulative_work: u128,
    pub(super) stamped: bool,
}

impl Store {
    /// `keep` is the shares to retain on disk, or none to retain every one.
    pub(super) fn open(path: &Path, keep: Option<u64>, chain: Option<&str>) -> io::Result<Self> {
        let db = create_database(path)?;
        let w = db.begin_write().db()?;
        let mut stamped = false;
        let cumulative_work: u128;
        {
            let held_shares = !w.open_table(SHARES).db()?.is_empty().db()?;
            w.delete_table(RETIRED_BY_HASH).db()?;
            let mut meta = w.open_table(META).db()?;
            if let Some(chain) = chain {
                let stored = meta.get(META_CHAIN).db()?.map(|v| v.value().to_string());
                match stored {
                    Some(stored) if stored != chain => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "{} holds shares for chain {stored}, but the node is on chain \
                                 {chain}; a ledger serves one chain, so move it out of the \
                                 data directory",
                                path.display()
                            ),
                        ));
                    }
                    Some(_) => {}
                    None => {
                        meta.insert(META_CHAIN, chain).db()?;
                        stamped = held_shares;
                    }
                }
            }
            cumulative_work = meta
                .get(META_CUMULATIVE_WORK)
                .db()?
                .and_then(|v| v.value().parse().ok())
                .unwrap_or(0);
        }
        w.commit().db()?;
        let next_seq = {
            let r = db.begin_read().db()?;
            let shares = r.open_table(SHARES).db()?;
            shares.last().db()?.map_or(0, |(k, _)| k.value() + 1)
        };
        Ok(Self { db, next_seq, retain_bound: keep, cumulative_work, stamped })
    }

    pub(super) fn database(&self) -> Arc<Database> {
        Arc::clone(&self.db)
    }

    /// Stores the share under the next sequence number with `cumulative_work`, the
    /// ledger's counter as it stands with this share.
    pub(super) fn insert(&mut self, share: &Share, cumulative_work: u128) -> io::Result<()> {
        write(&self.db, |w| {
            w.open_table(SHARES).db()?.insert(self.next_seq, pack(share).as_slice()).db()?;
            w.open_table(META)
                .db()?
                .insert(META_CUMULATIVE_WORK, cumulative_work.to_string().as_str())
                .db()?;
            Ok(())
        })?;
        self.next_seq += 1;
        Ok(())
    }

    /// Passes `f` the newest shares whose difficulties reach `window`, oldest first, and at
    /// most `max_shares` of them: the ledger discards anything past its own count bound, so
    /// reading further would only be trimmed again. Both passes read one snapshot. The first
    /// walks back from the newest row summing difficulties to find the row the window starts
    /// at, and gives `f` the number of shares it counted, so a buffer is sized once; the
    /// second walks forward from it, so no share outlives its call to `f`.
    pub(super) fn read_window(
        &self,
        window: u128,
        max_shares: usize,
        mut f: impl FnMut(WindowRow),
    ) -> io::Result<ReadBack> {
        let r = self.db.begin_read().db()?;
        let shares = r.open_table(SHARES).db()?;
        let mut read_back = ReadBack::default();
        let mut work = 0u128;
        let mut counted = 0usize;
        let mut start = None;
        let mut hit_count_cap = false;
        let mut iter = shares.iter().db()?;
        while work < window {
            if counted >= max_shares {
                hit_count_cap = true;
                break;
            }
            let Some(entry) = iter.next_back() else { break };
            let (seq, value) = entry.db()?;
            match unpack_head(value.value()) {
                Some(head) => {
                    work = work.saturating_add(u128::from(head.difficulty));
                    counted += 1;
                    start = Some(seq.value());
                }
                None => read_back.skipped += 1,
            }
        }
        read_back.truncated = work < window && !hit_count_cap;
        let Some(start) = start else { return Ok(read_back) };
        f(WindowRow::Count(counted));
        for entry in shares.range(start..).db()? {
            let (_seq, value) = entry.db()?;
            if let Some(share) = unpack(value.value()) {
                f(WindowRow::Share(share));
            }
        }
        Ok(read_back)
    }

    /// The acceptance time and block hash of the shares accepted at or after `cutoff`, at most
    /// `max` of them, oldest first. Rows are stored in the order they were recorded, so the
    /// scan from the newest stops at the first row older than `cutoff`: every row recorded
    /// before it is older still, unless the pool's clock stepped back between the two.
    pub(super) fn accepted_since(
        &self,
        cutoff: u64,
        max: usize,
    ) -> io::Result<Vec<(u64, [u8; 32])>> {
        let r = self.db.begin_read().db()?;
        let shares = r.open_table(SHARES).db()?;
        let mut collected = Vec::new();
        let mut iter = shares.iter().db()?;
        while collected.len() < max {
            let Some(entry) = iter.next_back() else { break };
            let (_seq, value) = entry.db()?;
            let Some(head) = unpack_head(value.value()) else { continue };
            if head.accepted_at < cutoff {
                break;
            }
            collected.push((head.accepted_at, head.block_hash));
        }
        collected.reverse();
        Ok(collected)
    }

    /// Removes the oldest rows past what `--ledger-keep-shares` asks to retain, never
    /// dropping below `floor`, the shares the window holds, and never a row accepted at or
    /// after `keep_after` among the newest `keep_newest`. The window reads itself back from
    /// these rows, so retention below it would shrink the payout set the next time a rising
    /// network difficulty widens the window; and at startup the duplicate check reads back the
    /// newest `keep_newest` hashes accepted within `ACCEPTED_HASH_RETENTION_SECS`, so those
    /// rows must stay for a resend of their share to be refused after a restart. Disk cannot
    /// be bounded below what these need, so the configured figure is a request and both floors
    /// override it. At most `MAX_RETAINED_PER_CALL` rows go per call. The rows to remove are
    /// found in a read transaction, so a call that removes none commits nothing.
    pub(super) fn retain(
        &self,
        floor: u64,
        keep_after: u64,
        keep_newest: usize,
    ) -> io::Result<usize> {
        let Some(configured) = self.retain_bound else { return Ok(0) };
        let oldest = {
            let r = self.db.begin_read().db()?;
            let shares = r.open_table(SHARES).db()?;
            let count = shares.len().db()?;
            let surplus = count.saturating_sub(configured.max(floor)).min(MAX_RETAINED_PER_CALL);
            let recent_from = count.saturating_sub(keep_newest as u64);
            let mut oldest = Vec::new();
            for (position, entry) in shares.iter().db()?.take(surplus as usize).enumerate() {
                let (seq, value) = entry.db()?;
                let read_back = position as u64 >= recent_from
                    && unpack_head(value.value()).is_some_and(|h| h.accepted_at >= keep_after);
                if read_back {
                    break;
                }
                oldest.push(seq.value());
            }
            oldest
        };
        if oldest.is_empty() {
            return Ok(0);
        }
        write(&self.db, |w| {
            let mut shares = w.open_table(SHARES).db()?;
            for seq in &oldest {
                shares.remove(*seq).db()?;
            }
            Ok(oldest.len())
        })
    }
}

/// Opened writable (`open_database`) rather than read-only: a pool stopped by a signal leaves
/// the file not closed cleanly, which only a writable open repairs.
pub(super) fn dump_file(path: &Path, f: impl FnMut(Share) -> io::Result<()>) -> io::Result<()> {
    dump(&open_database(path)?, f)
}

/// Passes `f` each stored share, oldest first, and stops at the first error it returns.
fn dump(db: &impl ReadableDatabase, mut f: impl FnMut(Share) -> io::Result<()>) -> io::Result<()> {
    let r = db.begin_read().db()?;
    let shares = r.open_table(SHARES).db()?;
    for entry in shares.iter().db()? {
        let (_seq, value) = entry.db()?;
        if let Some(share) = unpack(value.value()) {
            f(share)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{Scratch, hash};

    fn dumped(db: &Database) -> Vec<Share> {
        let mut out = Vec::new();
        dump(db, |share| {
            out.push(share);
            Ok(())
        })
        .unwrap();
        out
    }

    #[test]
    fn packs_and_unpacks_a_share() {
        let share = Share {
            accepted_at: 1_750_000_000,
            identity: "bc1qexample".into(),
            difficulty: 16384,
            block_hash: hash(7),
            tag_secondary: "garage".into(),
        };
        assert_eq!(unpack(&pack(&share)), Some(share.clone()));
        let untagged = Share { tag_secondary: String::new(), ..share.clone() };
        let mut bytes = pack(&untagged);
        assert_eq!(bytes.pop(), Some(0x00), "the separator is the last byte when the tag is empty");
        assert_eq!(unpack(&bytes), Some(untagged));
        assert_eq!(unpack(&[0u8; 16]), None);
    }

    #[test]
    fn opening_a_ledger_deletes_the_retired_hash_index() {
        let scratch = Scratch::new("retired-index");
        let path = scratch.join("regtest.redb");
        {
            let db = create_database(&path).unwrap();
            write(&db, |w| {
                w.open_table(RETIRED_BY_HASH).db()?.insert([7u8; 32].as_slice(), 0).db()?;
                Ok(())
            })
            .unwrap();
        }
        let store = Store::open(&path, None, None).unwrap();
        let r = store.db.begin_read().unwrap();
        assert!(r.open_table(RETIRED_BY_HASH).is_err(), "the table is gone");
    }

    /// Only the newest `keep_newest` recent rows are read back at startup, so only those are
    /// kept past the configured count.
    #[test]
    fn retention_keeps_recent_rows_only_as_far_as_they_are_read_back() {
        let scratch = Scratch::new("retain-read-back");
        let mut store = Store::open(&scratch.join("regtest.redb"), Some(2), None).unwrap();
        for i in 0..10u64 {
            let share = Share {
                accepted_at: 5_000,
                identity: "m".into(),
                difficulty: 16,
                block_hash: hash(i),
                tag_secondary: String::new(),
            };
            store.insert(&share, 16 * (i + 1) as u128).unwrap();
        }
        assert_eq!(
            store.retain(0, 5_000, 5).unwrap(),
            5,
            "every row is recent; five are read back"
        );
        assert_eq!(store.retain(0, 5_000, 5).unwrap(), 0, "and nothing further goes");
        assert_eq!(dumped(&store.db).first().unwrap().block_hash, hash(5));
    }

    #[test]
    fn retention_keeps_the_most_recent_shares() {
        let scratch = Scratch::new("retain");
        let mut store = Store::open(&scratch.join("regtest.redb"), None, None).unwrap();
        store.retain_bound = Some(5);
        let (floor, keep_after, keep_newest) = (0, u64::MAX, 0);
        for i in 0..12u64 {
            let share = Share {
                accepted_at: i,
                identity: "m".into(),
                difficulty: 16,
                block_hash: hash(i),
                tag_secondary: String::new(),
            };
            store.insert(&share, 16 * (i + 1) as u128).unwrap();
            store.retain(floor, keep_after, keep_newest).unwrap();
        }
        let dumped = dumped(&store.db);
        assert_eq!(dumped.len(), 5, "only the five most recent are retained");
        assert_eq!(dumped.first().unwrap().accepted_at, 7, "the oldest kept");
        assert_eq!(dumped.last().unwrap().accepted_at, 11, "through the newest");
    }
}
