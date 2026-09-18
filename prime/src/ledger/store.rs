//! The share rows on disk, each under a sequence number, and the metadata beside them: the chain
//! the ledger serves and the running total of credited work.

use super::db::{DbResult as _, NAME_SEPARATOR, create_database, split_at_separator, write};
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
                                 {chain}; a ledger serves one chain, so give --ledger a file \
                                 of {chain} shares",
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

    /// The newest shares whose difficulties reach `window`, oldest first, and at most
    /// `max_shares` of them: the ledger discards anything past its own count bound, so
    /// reading further would only be trimmed again.
    pub(super) fn read_back(
        &self,
        window: u128,
        max_shares: usize,
    ) -> io::Result<(Vec<Share>, ReadBack)> {
        let r = self.db.begin_read().db()?;
        let shares = r.open_table(SHARES).db()?;
        let mut collected = Vec::new();
        let mut work = 0u128;
        let mut read_back = ReadBack::default();
        let mut iter = shares.iter().db()?;
        let mut hit_count_cap = false;
        while work < window {
            if collected.len() >= max_shares {
                hit_count_cap = true;
                break;
            }
            let Some(entry) = iter.next_back() else { break };
            let (_seq, value) = entry.db()?;
            match unpack(value.value()) {
                Some(share) => {
                    work = work.saturating_add(u128::from(share.difficulty));
                    collected.push(share);
                }
                None => read_back.skipped += 1,
            }
        }
        read_back.truncated = work < window && !hit_count_cap;
        collected.reverse();
        Ok((collected, read_back))
    }

    /// Removes the oldest rows past what `--ledger-keep-shares` asks to retain, never
    /// dropping below `floor`, the shares the window holds. The window reads itself back from
    /// these rows, so retention below it would shrink the payout set the next time a rising
    /// network difficulty widens the window. Disk cannot be bounded below what the window
    /// needs, so the configured figure is a request and this floor overrides it.
    pub(super) fn retain(&self, floor: u64) -> io::Result<usize> {
        let Some(configured) = self.retain_bound else { return Ok(0) };
        let retain = configured.max(floor);
        let count = {
            let r = self.db.begin_read().db()?;
            r.open_table(SHARES).db()?.len().db()?
        };
        let Some(surplus) = count.checked_sub(retain) else { return Ok(0) };
        if surplus == 0 {
            return Ok(0);
        }
        write(&self.db, |w| {
            let mut shares = w.open_table(SHARES).db()?;
            let oldest = shares
                .iter()
                .db()?
                .take(surplus as usize)
                .map(|entry| entry.map(|(seq, _)| seq.value()).db())
                .collect::<io::Result<Vec<u64>>>()?;
            for seq in &oldest {
                shares.remove(*seq).db()?;
            }
            Ok(oldest.len())
        })
    }
}

/// `Database::open` rather than `ReadOnlyDatabase::open`: a pool stopped by a signal leaves
/// the file not closed cleanly, which only a writable open repairs.
pub(super) fn dump_file(path: &Path) -> io::Result<Vec<Share>> {
    dump(&Database::open(path).db()?)
}

fn dump(db: &impl ReadableDatabase) -> io::Result<Vec<Share>> {
    let r = db.begin_read().db()?;
    let shares = r.open_table(SHARES).db()?;
    let mut out = Vec::new();
    for entry in shares.iter().db()? {
        let (_seq, value) = entry.db()?;
        if let Some(share) = unpack(value.value()) {
            out.push(share);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{Scratch, hash};

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

    #[test]
    fn retention_keeps_the_most_recent_shares() {
        let scratch = Scratch::new("retain");
        let mut store = Store::open(&scratch.join("regtest.redb"), None, None).unwrap();
        store.retain_bound = Some(5);
        let floor = 0;
        for i in 0..12u64 {
            let share = Share {
                accepted_at: i,
                identity: "m".into(),
                difficulty: 16,
                block_hash: hash(i),
                tag_secondary: String::new(),
            };
            store.insert(&share, 16 * (i + 1) as u128).unwrap();
            store.retain(floor).unwrap();
        }
        let dumped = dump(&*store.db).unwrap();
        assert_eq!(dumped.len(), 5, "only the five most recent are retained");
        assert_eq!(dumped.first().unwrap().accepted_at, 7, "the oldest kept");
        assert_eq!(dumped.last().unwrap().accepted_at, 11, "through the newest");
    }
}
