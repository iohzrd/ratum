use super::{FoundBlock, HASH_SIZE, MAX_SHARES, OwedBlock, ReadBack, SHARES_PER_KEEP_UNIT, Share};
use bytes::BufMut as _;
use ratum::cursor::Cursor;
use redb::{
    Database, Durability, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
};
use std::io;
use std::path::Path;

const SHARES: TableDefinition<u64, &[u8]> = TableDefinition::new("shares");
const BY_HASH: TableDefinition<&[u8], u64> = TableDefinition::new("by_hash");
const BLOCKS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blocks");
const OWED: TableDefinition<&[u8], &[u8]> = TableDefinition::new("owed");

const META: TableDefinition<&str, &str> = TableDefinition::new("meta");
const META_CHAIN: &str = "chain";
const META_CUMULATIVE_WORK: &str = "cumulative_work";

const NAME_SEPARATOR: u8 = 0x00;

fn pack(share: &Share) -> Vec<u8> {
    let hash = share.hash.unwrap_or([0u8; HASH_SIZE]);
    let mut v = Vec::with_capacity(SHARE_PREFIX_LEN + 1 + share.identity.len() + share.tag.len());
    v.put_u64_le(share.at);
    v.put_u64_le(share.difficulty);
    v.put_slice(&hash);
    v.put_slice(share.identity.as_bytes());
    v.put_u8(NAME_SEPARATOR);
    v.put_slice(share.tag.as_bytes());
    v
}

const SHARE_PREFIX_LEN: usize = 2 * size_of::<u64>() + HASH_SIZE;
const SHARE_HASH_AT: std::ops::Range<usize> = SHARE_PREFIX_LEN - HASH_SIZE..SHARE_PREFIX_LEN;

fn unpack(bytes: &[u8]) -> Option<Share> {
    let mut c = Cursor::new(bytes);
    let at = c.u64("at").ok()?;
    let difficulty = c.u64("difficulty").ok()?;
    let hash: [u8; HASH_SIZE] = c.arr("hash").ok()?;
    let (identity, tag) = split_at_separator(c.rest());
    Some(Share {
        at,
        identity: String::from_utf8_lossy(identity).into_owned(),
        difficulty,
        hash: Some(hash),
        tag: String::from_utf8_lossy(tag).into_owned(),
    })
}

fn split_at_separator(rest: &[u8]) -> (&[u8], &[u8]) {
    match rest.iter().position(|&b| b == NAME_SEPARATOR) {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, [].as_slice()),
    }
}

fn pack_owed(o: &OwedBlock) -> Vec<u8> {
    let entries: usize = o.entries.iter().map(|(i, _)| OWED_ENTRY_PREFIX_LEN + i.len()).sum();
    let mut v = Vec::with_capacity(OWED_PREFIX_LEN + entries);
    v.put_u64_le(o.at);
    v.put_u32_le(o.height);
    v.put_u64_le(o.total);
    v.put_u64_le(o.settled_at.unwrap_or(0));
    v.put_u16_le(o.entries.len() as u16);
    for (identity, sats) in &o.entries {
        v.put_u16_le(identity.len() as u16);
        v.put_slice(identity.as_bytes());
        v.put_u64_le(*sats);
    }
    v
}

const OWED_PREFIX_LEN: usize =
    size_of::<u64>() + size_of::<u32>() + 2 * size_of::<u64>() + size_of::<u16>();
const OWED_ENTRY_PREFIX_LEN: usize = size_of::<u16>() + size_of::<u64>();

fn unpack_owed(hash: &[u8], bytes: &[u8]) -> Option<OwedBlock> {
    let block_hash: [u8; HASH_SIZE] = hash.try_into().ok()?;
    let mut c = Cursor::new(bytes);
    let at = c.u64("at").ok()?;
    let height = c.u32("height").ok()?;
    let total = c.u64("total").ok()?;
    let settled = c.u64("settled_at").ok()?;
    let count = c.u16("entry count").ok()?;
    let mut entries = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let len = c.u16("identity length").ok()? as usize;
        let identity = String::from_utf8_lossy(c.take(len, "identity").ok()?).into_owned();
        entries.push((identity, c.u64("sats").ok()?));
    }
    Some(OwedBlock {
        at,
        height,
        block_hash,
        total,
        settled_at: (settled != 0).then_some(settled),
        entries,
    })
}

fn pack_block(b: &FoundBlock) -> Vec<u8> {
    let mut v = Vec::with_capacity(BLOCK_PREFIX_LEN + 1 + b.finder.len() + b.tag.len());
    v.put_u64_le(b.at);
    v.put_u32_le(b.height);
    v.put_u64_le(b.paid_to_split);
    v.put_u64_le(b.paid_to_pool);
    v.put_f64_le(b.difficulty);
    v.put_u128_le(b.cumulative_work);
    v.put_slice(b.finder.as_bytes());
    v.put_u8(NAME_SEPARATOR);
    v.put_slice(b.tag.as_bytes());
    v
}

const BLOCK_PREFIX_LEN: usize =
    size_of::<u64>() + size_of::<u32>() + 3 * size_of::<u64>() + size_of::<u128>();

fn unpack_block(hash: &[u8], bytes: &[u8]) -> Option<FoundBlock> {
    let block_hash: [u8; HASH_SIZE] = hash.try_into().ok()?;
    let mut c = Cursor::new(bytes);
    let at = c.u64("at").ok()?;
    let height = c.u32("height").ok()?;
    let paid_to_split = c.u64("paid_to_split").ok()?;
    let paid_to_pool = c.u64("paid_to_pool").ok()?;
    let difficulty = f64::from_le_bytes(c.arr("difficulty").ok()?);
    let cumulative_work = u128::from_le_bytes(c.arr("cumulative work").ok()?);
    let (finder, tag) = split_at_separator(c.rest());
    Some(FoundBlock {
        at,
        height,
        block_hash,
        paid_to_split,
        paid_to_pool,
        difficulty,
        cumulative_work,
        finder: String::from_utf8_lossy(finder).into_owned(),
        tag: String::from_utf8_lossy(tag).into_owned(),
    })
}

trait DbResult<T> {
    fn db(self) -> io::Result<T>;
}

impl<T, E: std::fmt::Display> DbResult<T> for Result<T, E> {
    fn db(self) -> io::Result<T> {
        self.map_err(|e| io::Error::other(e.to_string()))
    }
}

pub(super) struct Store {
    db: Database,
    next_seq: u64,
    retain_bound: Option<u64>,
    pub(super) cumulative_work: u128,
}

impl Store {
    fn write<T>(&self, f: impl FnOnce(&redb::WriteTransaction) -> io::Result<T>) -> io::Result<T> {
        let mut w = self.db.begin_write().db()?;
        w.set_durability(Durability::Immediate).db()?;
        let out = f(&w)?;
        w.commit().db()?;
        Ok(out)
    }

    fn read_packed<T>(
        &self,
        table: TableDefinition<'static, &'static [u8], &'static [u8]>,
        what: &str,
        unpack: impl Fn(&[u8], &[u8]) -> Option<T>,
    ) -> io::Result<Vec<T>> {
        let r = self.db.begin_read().db()?;
        let table = r.open_table(table).db()?;
        let mut out = Vec::new();
        for entry in table.iter().db()? {
            let (key, value) = entry.db()?;
            match unpack(key.value(), value.value()) {
                Some(row) => out.push(row),
                None => log::warn!(
                    "skipping {what} row ({}) that did not unpack, which an uncorrupted \
                     database never produces",
                    hex::encode(key.value())
                ),
            }
        }
        Ok(out)
    }

    pub(super) fn open(
        path: &Path,
        keep: Option<usize>,
        chain: Option<&str>,
    ) -> io::Result<(Self, bool)> {
        let db = Database::create(path).db()?;
        let w = db.begin_write().db()?;
        let mut stamped = false;
        let cumulative_work: u128;
        {
            let held_shares = !w.open_table(SHARES).db()?.is_empty().db()?;
            w.open_table(BY_HASH).db()?;
            w.open_table(OWED).db()?;
            w.open_table(BLOCKS).db()?;
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
        let retain = keep.map(|k| (k.max(1) as u64).saturating_mul(SHARES_PER_KEEP_UNIT));
        Ok((Self { db, next_seq, retain_bound: retain, cumulative_work }, stamped))
    }

    pub(super) fn insert(&mut self, share: &Share) -> io::Result<bool> {
        let hash = share.hash.expect("a recorded share has a hash");
        let cumulative = self.cumulative_work + u128::from(share.difficulty);
        let inserted = self.write(|w| {
            let mut by_hash = w.open_table(BY_HASH).db()?;
            if by_hash.get(hash.as_slice()).db()?.is_some() {
                return Ok(false);
            }
            let seq = self.next_seq;
            w.open_table(SHARES).db()?.insert(seq, pack(share).as_slice()).db()?;
            by_hash.insert(hash.as_slice(), seq).db()?;
            w.open_table(META)
                .db()?
                .insert(META_CUMULATIVE_WORK, cumulative.to_string().as_str())
                .db()?;
            Ok(true)
        })?;
        if inserted {
            self.next_seq += 1;
            self.cumulative_work = cumulative;
        }
        Ok(inserted)
    }

    pub(super) fn read_back(&self, window: u128) -> io::Result<(Vec<Share>, ReadBack)> {
        let r = self.db.begin_read().db()?;
        let shares = r.open_table(SHARES).db()?;
        let mut collected = Vec::new();
        let mut work = 0u128;
        let mut read_back = ReadBack::default();
        let mut iter = shares.iter().db()?;
        let mut hit_count_cap = false;
        while work < window {
            if collected.len() >= MAX_SHARES {
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

    pub(super) fn retain(&self) -> io::Result<usize> {
        let Some(retain) = self.retain_bound else { return Ok(0) };
        let count = {
            let r = self.db.begin_read().db()?;
            r.open_table(SHARES).db()?.len().db()?
        };
        let Some(surplus) = count.checked_sub(retain) else { return Ok(0) };
        if surplus == 0 {
            return Ok(0);
        }
        self.write(|w| {
            let mut shares = w.open_table(SHARES).db()?;
            let mut by_hash = w.open_table(BY_HASH).db()?;
            let oldest: Vec<(u64, [u8; 32])> = shares
                .iter()
                .db()?
                .take(surplus as usize)
                .filter_map(|entry| {
                    let (seq, value) = entry.ok()?;
                    let hash = value.value().get(SHARE_HASH_AT)?.try_into().ok()?;
                    Some((seq.value(), hash))
                })
                .collect();
            let mut removed = 0usize;
            for (seq, hash) in oldest {
                shares.remove(seq).db()?;
                by_hash.remove(hash.as_slice()).db()?;
                removed += 1;
            }
            Ok(removed)
        })
    }

    pub(super) fn insert_block(&self, block: &FoundBlock) -> io::Result<bool> {
        self.write(|w| {
            let mut table = w.open_table(BLOCKS).db()?;
            if table.get(block.block_hash.as_slice()).db()?.is_some() {
                return Ok(false);
            }
            table.insert(block.block_hash.as_slice(), pack_block(block).as_slice()).db()?;
            Ok(true)
        })
    }

    pub(super) fn read_blocks(&self) -> io::Result<Vec<FoundBlock>> {
        let mut out = self.read_packed(BLOCKS, "a block", unpack_block)?;
        out.sort_by_key(|b| (b.at, b.height));
        Ok(out)
    }

    pub(super) fn write_owed(&self, owed: &OwedBlock) -> io::Result<()> {
        self.write(|w| {
            w.open_table(OWED)
                .db()?
                .insert(owed.block_hash.as_slice(), pack_owed(owed).as_slice())
                .db()?;
            Ok(())
        })
    }

    pub(super) fn remove_owed(&self, hash: &[u8; 32]) -> io::Result<()> {
        self.write(|w| {
            w.open_table(OWED).db()?.remove(hash.as_slice()).db()?;
            Ok(())
        })
    }

    pub(super) fn read_owed(&self) -> io::Result<Vec<OwedBlock>> {
        let mut out = self.read_packed(OWED, "an owed", unpack_owed)?;
        out.sort_by_key(|o| (o.at, o.height));
        Ok(out)
    }

    pub(super) fn dump(&self) -> io::Result<Vec<Share>> {
        let r = self.db.begin_read().db()?;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::tests::{Scratch, found, hash, owed};

    #[test]
    fn packs_and_unpacks_a_share() {
        let share = Share {
            at: 1_750_000_000,
            identity: "bc1qexample".into(),
            difficulty: 16384,
            hash: Some(hash(7)),
            tag: "garage".into(),
        };
        assert_eq!(unpack(&pack(&share)), Some(share.clone()));
        let untagged = Share { tag: String::new(), ..share.clone() };
        let mut bytes = pack(&untagged);
        assert_eq!(bytes.pop(), Some(0x00), "the separator is the last byte when the tag is empty");
        assert_eq!(unpack(&bytes), Some(untagged));
        assert_eq!(unpack(&[0u8; 16]), None);
    }
    #[test]
    fn an_owed_block_round_trips_through_pack() {
        for o in
            [owed(1, None), owed(2, Some(4_000)), OwedBlock { entries: vec![], ..owed(3, None) }]
        {
            assert_eq!(unpack_owed(&o.block_hash, &pack_owed(&o)), Some(o));
        }
    }
    #[test]
    fn a_found_block_round_trips_through_pack() {
        for b in [
            found(1, 0),
            found(2, u128::MAX),
            FoundBlock { finder: String::new(), ..found(3, 7) },
            FoundBlock { tag: String::new(), ..found(4, 9) },
        ] {
            assert_eq!(unpack_block(&b.block_hash, &pack_block(&b)), Some(b));
        }
    }
    #[test]
    fn a_block_row_without_the_tag_separator_reads_back_with_an_empty_tag() {
        let b = FoundBlock { tag: String::new(), ..found(1, 48) };
        let mut bytes = pack_block(&b);
        assert_eq!(bytes.pop(), Some(0x00), "the separator is the last byte when the tag is empty");
        assert_eq!(unpack_block(&b.block_hash, &bytes), Some(b));
    }

    #[test]
    fn retention_keeps_the_most_recent_shares() {
        let scratch = Scratch::new("retain");
        let (mut store, _) = Store::open(&scratch.join("regtest.redb"), None, None).unwrap();
        store.retain_bound = Some(5);
        for i in 0..12u64 {
            let share = Share {
                at: i,
                identity: "m".into(),
                difficulty: 16,
                hash: Some(hash(i)),
                tag: String::new(),
            };
            store.insert(&share).unwrap();
            store.retain().unwrap();
        }
        let dumped = store.dump().unwrap();
        assert_eq!(dumped.len(), 5, "only the five most recent are retained");
        assert_eq!(dumped.first().unwrap().at, 7, "the oldest kept");
        assert_eq!(dumped.last().unwrap().at, 11, "through the newest");
        assert!(
            store
                .insert(&Share {
                    at: 0,
                    identity: "m".into(),
                    difficulty: 16,
                    hash: Some(hash(0)),
                    tag: String::new(),
                })
                .unwrap()
        );
    }
}
