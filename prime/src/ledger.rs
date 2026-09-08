use ratum::cursor::Cursor;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::path::Path;

use redb::{
    Database, Durability, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
};

const MAX_SHARES: usize = 1 << 20;

pub const SHARES_PER_KEEP_UNIT: u64 = MAX_SHARES as u64;

const SHARES: TableDefinition<u64, &[u8]> = TableDefinition::new("shares");

const BY_HASH: TableDefinition<&[u8], u64> = TableDefinition::new("by_hash");

const META: TableDefinition<&str, &str> = TableDefinition::new("meta");
const META_CHAIN: &str = "chain";
const META_CUMULATIVE_WORK: &str = "cumulative_work";

const BLOCKS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blocks");

const OWED: TableDefinition<&[u8], &[u8]> = TableDefinition::new("owed");

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    pub at: u64,
    pub identity: String,
    pub difficulty: u64,
    pub hash: Option<[u8; 32]>,
    pub tag: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadBack {
    pub skipped: usize,
    pub truncated: bool,
    pub stamped: bool,
}

fn pack(share: &Share) -> Vec<u8> {
    let hash = share.hash.unwrap_or([0u8; HASH_SIZE]);
    let mut v = Vec::with_capacity(SHARE_PREFIX_LEN + 1 + share.identity.len() + share.tag.len());
    v.extend_from_slice(&share.at.to_le_bytes());
    v.extend_from_slice(&share.difficulty.to_le_bytes());
    v.extend_from_slice(&hash);
    v.extend_from_slice(share.identity.as_bytes());
    v.push(NAME_SEPARATOR);
    v.extend_from_slice(share.tag.as_bytes());
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

const NAME_SEPARATOR: u8 = 0x00;

const HASH_SIZE: usize = ratum::bitcoin::HASH_SIZE;

fn split_at_separator(rest: &[u8]) -> (&[u8], &[u8]) {
    match rest.iter().position(|&b| b == NAME_SEPARATOR) {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, [].as_slice()),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwedBlock {
    pub at: u64,
    pub height: u32,
    pub block_hash: [u8; 32],
    pub total: u64,
    pub settled_at: Option<u64>,
    pub entries: Vec<(String, u64)>,
}

fn pack_owed(o: &OwedBlock) -> Vec<u8> {
    let entries: usize = o.entries.iter().map(|(i, _)| OWED_ENTRY_PREFIX_LEN + i.len()).sum();
    let mut v = Vec::with_capacity(OWED_PREFIX_LEN + entries);
    v.extend_from_slice(&o.at.to_le_bytes());
    v.extend_from_slice(&o.height.to_le_bytes());
    v.extend_from_slice(&o.total.to_le_bytes());
    v.extend_from_slice(&o.settled_at.unwrap_or(0).to_le_bytes());
    v.extend_from_slice(&(o.entries.len() as u16).to_le_bytes());
    for (identity, sats) in &o.entries {
        v.extend_from_slice(&(identity.len() as u16).to_le_bytes());
        v.extend_from_slice(identity.as_bytes());
        v.extend_from_slice(&sats.to_le_bytes());
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

#[derive(Clone, Debug, PartialEq)]
pub struct FoundBlock {
    pub at: u64,
    pub height: u32,
    pub block_hash: [u8; 32],
    pub paid_to_split: u64,
    pub paid_to_pool: u64,
    pub finder: String,
    pub tag: String,
    pub difficulty: f64,
    pub cumulative_work: u128,
}

fn pack_block(b: &FoundBlock) -> Vec<u8> {
    let mut v = Vec::with_capacity(BLOCK_PREFIX_LEN + 1 + b.finder.len() + b.tag.len());
    v.extend_from_slice(&b.at.to_le_bytes());
    v.extend_from_slice(&b.height.to_le_bytes());
    v.extend_from_slice(&b.paid_to_split.to_le_bytes());
    v.extend_from_slice(&b.paid_to_pool.to_le_bytes());
    v.extend_from_slice(&b.difficulty.to_bits().to_le_bytes());
    v.extend_from_slice(&b.cumulative_work.to_le_bytes());
    v.extend_from_slice(b.finder.as_bytes());
    v.push(NAME_SEPARATOR);
    v.extend_from_slice(b.tag.as_bytes());
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
    let difficulty = f64::from_bits(c.u64("difficulty").ok()?);
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

fn to_io(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

struct Store {
    db: Database,
    next_seq: u64,
    retain_bound: Option<u64>,
    cumulative_work: u128,
}

impl Store {
    fn write<T>(&self, f: impl FnOnce(&redb::WriteTransaction) -> io::Result<T>) -> io::Result<T> {
        let mut w = self.db.begin_write().map_err(to_io)?;
        w.set_durability(Durability::Immediate).map_err(to_io)?;
        let out = f(&w)?;
        w.commit().map_err(to_io)?;
        Ok(out)
    }

    fn read_packed<T>(
        &self,
        table: TableDefinition<'static, &'static [u8], &'static [u8]>,
        what: &str,
        unpack: impl Fn(&[u8], &[u8]) -> Option<T>,
    ) -> io::Result<Vec<T>> {
        let r = self.db.begin_read().map_err(to_io)?;
        let table = r.open_table(table).map_err(to_io)?;
        let mut out = Vec::new();
        for entry in table.iter().map_err(to_io)? {
            let (key, value) = entry.map_err(to_io)?;
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

    fn open(path: &Path, keep: Option<usize>, chain: Option<&str>) -> io::Result<(Self, bool)> {
        let db = Database::create(path).map_err(to_io)?;
        let w = db.begin_write().map_err(to_io)?;
        let mut stamped = false;
        let cumulative_work: u128;
        {
            let held_shares = !w.open_table(SHARES).map_err(to_io)?.is_empty().map_err(to_io)?;
            w.open_table(BY_HASH).map_err(to_io)?;
            w.open_table(OWED).map_err(to_io)?;
            w.open_table(BLOCKS).map_err(to_io)?;
            let mut meta = w.open_table(META).map_err(to_io)?;
            if let Some(chain) = chain {
                let stored = meta.get(META_CHAIN).map_err(to_io)?.map(|v| v.value().to_string());
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
                        meta.insert(META_CHAIN, chain).map_err(to_io)?;
                        stamped = held_shares;
                    }
                }
            }
            cumulative_work = meta
                .get(META_CUMULATIVE_WORK)
                .map_err(to_io)?
                .and_then(|v| v.value().parse().ok())
                .unwrap_or(0);
        }
        w.commit().map_err(to_io)?;
        let next_seq = {
            let r = db.begin_read().map_err(to_io)?;
            let shares = r.open_table(SHARES).map_err(to_io)?;
            shares.last().map_err(to_io)?.map_or(0, |(k, _)| k.value() + 1)
        };
        let retain = keep.map(|k| (k.max(1) as u64).saturating_mul(SHARES_PER_KEEP_UNIT));
        Ok((Store { db, next_seq, retain_bound: retain, cumulative_work }, stamped))
    }

    fn insert(&mut self, share: &Share) -> io::Result<bool> {
        let hash = share.hash.expect("a recorded share has a hash");
        let cumulative = self.cumulative_work + u128::from(share.difficulty);
        let inserted = self.write(|w| {
            let mut by_hash = w.open_table(BY_HASH).map_err(to_io)?;
            if by_hash.get(hash.as_slice()).map_err(to_io)?.is_some() {
                return Ok(false);
            }
            let seq = self.next_seq;
            w.open_table(SHARES)
                .map_err(to_io)?
                .insert(seq, pack(share).as_slice())
                .map_err(to_io)?;
            by_hash.insert(hash.as_slice(), seq).map_err(to_io)?;
            w.open_table(META)
                .map_err(to_io)?
                .insert(META_CUMULATIVE_WORK, cumulative.to_string().as_str())
                .map_err(to_io)?;
            Ok(true)
        })?;
        if inserted {
            self.next_seq += 1;
            self.cumulative_work = cumulative;
        }
        Ok(inserted)
    }

    fn read_back(&self, window: u128) -> io::Result<(Vec<Share>, ReadBack)> {
        let r = self.db.begin_read().map_err(to_io)?;
        let shares = r.open_table(SHARES).map_err(to_io)?;
        let mut collected = Vec::new();
        let mut work = 0u128;
        let mut read_back = ReadBack::default();
        let mut iter = shares.iter().map_err(to_io)?;
        let mut hit_count_cap = false;
        while work < window {
            if collected.len() >= MAX_SHARES {
                hit_count_cap = true;
                break;
            }
            let Some(entry) = iter.next_back() else { break };
            let (_seq, value) = entry.map_err(to_io)?;
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

    fn retain(&mut self) -> io::Result<usize> {
        let Some(retain) = self.retain_bound else { return Ok(0) };
        let count = {
            let r = self.db.begin_read().map_err(to_io)?;
            r.open_table(SHARES).map_err(to_io)?.len().map_err(to_io)?
        };
        let Some(surplus) = count.checked_sub(retain) else { return Ok(0) };
        if surplus == 0 {
            return Ok(0);
        }
        self.write(|w| {
            let mut shares = w.open_table(SHARES).map_err(to_io)?;
            let mut by_hash = w.open_table(BY_HASH).map_err(to_io)?;
            let oldest: Vec<(u64, [u8; 32])> = shares
                .iter()
                .map_err(to_io)?
                .take(surplus as usize)
                .filter_map(|entry| {
                    let (seq, value) = entry.ok()?;
                    let hash = value.value().get(SHARE_HASH_AT)?.try_into().ok()?;
                    Some((seq.value(), hash))
                })
                .collect();
            let mut removed = 0usize;
            for (seq, hash) in oldest {
                shares.remove(seq).map_err(to_io)?;
                by_hash.remove(hash.as_slice()).map_err(to_io)?;
                removed += 1;
            }
            Ok(removed)
        })
    }

    fn insert_block(&mut self, block: &FoundBlock) -> io::Result<bool> {
        self.write(|w| {
            let mut table = w.open_table(BLOCKS).map_err(to_io)?;
            if table.get(block.block_hash.as_slice()).map_err(to_io)?.is_some() {
                return Ok(false);
            }
            table
                .insert(block.block_hash.as_slice(), pack_block(block).as_slice())
                .map_err(to_io)?;
            Ok(true)
        })
    }

    fn read_blocks(&self) -> io::Result<Vec<FoundBlock>> {
        let mut out = self.read_packed(BLOCKS, "a block", unpack_block)?;
        out.sort_by_key(|b| (b.at, b.height));
        Ok(out)
    }

    fn write_owed(&mut self, owed: &OwedBlock) -> io::Result<()> {
        self.write(|w| {
            w.open_table(OWED)
                .map_err(to_io)?
                .insert(owed.block_hash.as_slice(), pack_owed(owed).as_slice())
                .map_err(to_io)?;
            Ok(())
        })
    }

    fn remove_owed(&mut self, hash: &[u8; 32]) -> io::Result<()> {
        self.write(|w| {
            w.open_table(OWED).map_err(to_io)?.remove(hash.as_slice()).map_err(to_io)?;
            Ok(())
        })
    }

    fn read_owed(&self) -> io::Result<Vec<OwedBlock>> {
        let mut out = self.read_packed(OWED, "an owed", unpack_owed)?;
        out.sort_by_key(|o| (o.at, o.height));
        Ok(out)
    }

    fn dump(&self) -> io::Result<Vec<Share>> {
        let r = self.db.begin_read().map_err(to_io)?;
        let shares = r.open_table(SHARES).map_err(to_io)?;
        let mut out = Vec::new();
        for entry in shares.iter().map_err(to_io)? {
            let (_seq, value) = entry.map_err(to_io)?;
            if let Some(share) = unpack(value.value()) {
                out.push(share);
            }
        }
        Ok(out)
    }
}

pub struct Ledger {
    removed: usize,
    shares: VecDeque<Share>,
    work_per_identity: HashMap<String, u128>,
    tag_per_identity: HashMap<String, String>,
    total_work: u128,
    window: u128,
    store: Option<Store>,
    owed: Vec<OwedBlock>,
    blocks: Vec<FoundBlock>,
    cumulative_work: u128,
    count_capped: bool,
}

impl Ledger {
    pub fn new(window: u128) -> Self {
        Ledger {
            removed: 0,
            shares: VecDeque::new(),
            work_per_identity: HashMap::new(),
            tag_per_identity: HashMap::new(),
            total_work: 0,
            window: window.max(1),
            store: None,
            owed: Vec::new(),
            blocks: Vec::new(),
            cumulative_work: 0,
            count_capped: false,
        }
    }

    pub fn open(
        path: &Path,
        window: u128,
        keep: Option<usize>,
        chain: Option<&str>,
    ) -> io::Result<(Self, ReadBack)> {
        let mut ledger = Ledger::new(window);
        let (store, stamped) = Store::open(path, keep, chain)?;
        let (shares, mut read_back) = store.read_back(ledger.window)?;
        read_back.stamped = stamped;
        ledger.fill(shares);
        ledger.owed = store.read_owed()?;
        ledger.blocks = store.read_blocks()?;
        ledger.cumulative_work = store.cumulative_work;
        ledger.store = Some(store);
        Ok((ledger, read_back))
    }

    pub fn set_window(&mut self, window: u128) -> usize {
        let window = window.max(1);
        let widened = window > self.window;
        self.window = window;
        let re_read = if widened { self.refill() } else { 0 };
        self.trim();
        re_read
    }

    fn refill(&mut self) -> usize {
        let before = self.shares.len();
        let (shares, read_back) = match self.store.as_ref() {
            Some(store) => match store.read_back(self.window) {
                Ok(v) => v,
                Err(e) => {
                    log::warn!("could not re-read the ledger to widen the share window: {e}");
                    return 0;
                }
            },
            None => return 0,
        };
        if read_back.truncated {
            log::warn!(
                "the wider share window exceeds the retained ledger; work older than \
                 that is not credited (raise --ledger-keep to keep it)"
            );
        }
        self.fill(shares);
        self.shares.len().saturating_sub(before)
    }

    /// Replaces the in-memory window with `shares`, oldest first.
    fn fill(&mut self, shares: Vec<Share>) {
        self.shares.clear();
        self.work_per_identity.clear();
        self.tag_per_identity.clear();
        self.total_work = 0;
        for share in shares {
            self.push(share);
            self.trim();
        }
    }

    pub fn dump(&self) -> io::Result<Vec<Share>> {
        match &self.store {
            Some(store) => store.dump(),
            None => Ok(Vec::new()),
        }
    }

    pub fn window(&self) -> u128 {
        self.window
    }

    pub fn total_work(&self) -> u128 {
        self.total_work
    }

    pub fn len(&self) -> usize {
        self.shares.len()
    }

    pub fn is_empty(&self) -> bool {
        self.shares.is_empty()
    }

    pub fn take_removed(&mut self) -> usize {
        std::mem::replace(&mut self.removed, 0)
    }

    pub fn hashes(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.shares.iter().filter_map(|s| s.hash.as_ref())
    }

    pub fn record(
        &mut self,
        at: u64,
        identity: &str,
        difficulty: u64,
        hash: &[u8; 32],
        tag: &str,
    ) -> io::Result<()> {
        let share = Share {
            at,
            identity: identity.to_string(),
            difficulty,
            hash: Some(*hash),
            tag: tag.to_string(),
        };
        if let Some(store) = &mut self.store
            && !store.insert(&share)?
        {
            return Ok(());
        }
        self.cumulative_work += u128::from(difficulty);
        self.push(share);
        self.trim();
        if let Some(store) = &mut self.store {
            match store.retain() {
                Ok(removed) => self.removed = removed,
                Err(e) => log::warn!("ledger retention failed; the share is recorded ({e})"),
            }
        }
        Ok(())
    }

    pub fn cumulative_work(&self) -> u128 {
        self.cumulative_work
    }

    pub fn record_block(&mut self, block: FoundBlock) -> io::Result<()> {
        if self.blocks.iter().any(|b| b.block_hash == block.block_hash) {
            return Ok(());
        }
        if let Some(store) = &mut self.store
            && !store.insert_block(&block)?
        {
            return Ok(());
        }
        self.blocks.push(block);
        Ok(())
    }

    pub fn blocks(&self) -> &[FoundBlock] {
        &self.blocks
    }

    pub fn record_owed(&mut self, owed: OwedBlock) -> io::Result<()> {
        if self.owed.iter().any(|o| o.block_hash == owed.block_hash) {
            return Ok(());
        }
        if let Some(store) = &mut self.store {
            store.write_owed(&owed)?;
        }
        self.owed.push(owed);
        Ok(())
    }

    pub fn owed(&self) -> &[OwedBlock] {
        &self.owed
    }

    pub fn settle_owed(&mut self, hash: &[u8; 32], at: u64) -> io::Result<Option<OwedBlock>> {
        let Some(index) = self.owed.iter().position(|o| o.block_hash == *hash) else {
            return Ok(None);
        };
        if self.owed[index].settled_at.is_some() {
            return Ok(Some(self.owed[index].clone()));
        }
        let mut owed = self.owed[index].clone();
        owed.settled_at = Some(at.max(1));
        if let Some(store) = &mut self.store {
            store.write_owed(&owed)?;
        }
        self.owed[index] = owed.clone();
        Ok(Some(owed))
    }

    pub fn void_owed(&mut self, hash: &[u8; 32]) -> io::Result<Option<OwedBlock>> {
        let Some(index) = self.owed.iter().position(|o| o.block_hash == *hash) else {
            return Ok(None);
        };
        if let Some(store) = &mut self.store {
            store.remove_owed(hash)?;
        }
        Ok(Some(self.owed.remove(index)))
    }

    pub fn work_since(&self, cutoff: u64) -> (u128, HashMap<String, u128>) {
        let mut total = 0u128;
        let mut by_identity: HashMap<String, u128> = HashMap::new();
        for s in self.shares.iter().rev() {
            if s.at < cutoff {
                break;
            }
            total += u128::from(s.difficulty);
            *by_identity.entry(s.identity.clone()).or_insert(0) += u128::from(s.difficulty);
        }
        (total, by_identity)
    }

    pub fn work_by_identity(&self) -> Vec<(String, u128)> {
        let mut v: Vec<(String, u128)> =
            self.work_per_identity.iter().map(|(k, d)| (k.clone(), *d)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v
    }

    pub fn tags_by_identity(&self) -> HashMap<String, String> {
        self.tag_per_identity.clone()
    }

    pub fn split(&self, value: u64, min_payout: u64, max_outputs: usize) -> Vec<(String, u64)> {
        if self.total_work == 0 || value == 0 || max_outputs == 0 {
            return Vec::new();
        }
        let mut kept = self.work_by_identity();
        kept.truncate(max_outputs);
        let mut work: u128 = kept.iter().map(|(_, w)| *w).sum();

        while let Some(w) = kept.last().map(|(_, w)| *w) {
            if work == 0 {
                kept.clear();
                break;
            }
            if u128::from(value).saturating_mul(w) / work >= u128::from(min_payout) {
                break;
            }
            work -= w;
            kept.pop();
        }

        let mut left = value;
        let mut out = Vec::with_capacity(kept.len());
        for (identity, w) in kept {
            if work == 0 {
                break;
            }
            let amount = (u128::from(left).saturating_mul(w) / work) as u64;
            left -= amount;
            work -= w;
            if amount != 0 {
                out.push((identity, amount));
            }
        }
        out
    }

    fn push(&mut self, share: Share) {
        self.total_work += u128::from(share.difficulty);
        *self.work_per_identity.entry(share.identity.clone()).or_insert(0) +=
            u128::from(share.difficulty);
        self.tag_per_identity.insert(share.identity.clone(), share.tag.clone());
        self.shares.push_back(share);
    }

    fn trim(&mut self) {
        while self.shares.len() > 1 && self.total_work > self.window {
            let over = self.total_work - self.window;
            let oldest_difficulty = u128::from(self.shares.front().expect("non-empty").difficulty);
            if oldest_difficulty > over {
                break;
            }
            self.drop_oldest();
        }
        let mut count_trimmed = false;
        while self.shares.len() > MAX_SHARES {
            self.drop_oldest();
            count_trimmed = true;
        }
        if count_trimmed {
            if !self.count_capped {
                self.count_capped = true;
                log::warn!(
                    "the share window is capped at {MAX_SHARES} shares, which hold less work \
                     than the configured window times network difficulty; miners are paid over \
                     the newest {MAX_SHARES} shares. Raise the assigned share difficulty to \
                     cover the intended span."
                );
            }
        } else {
            self.count_capped = false;
        }
    }

    fn drop_oldest(&mut self) {
        let Some(oldest) = self.shares.pop_front() else { return };
        self.total_work -= u128::from(oldest.difficulty);
        if let Some(d) = self.work_per_identity.get_mut(&oldest.identity) {
            *d -= u128::from(oldest.difficulty);
            if *d == 0 {
                self.work_per_identity.remove(&oldest.identity);
                self.tag_per_identity.remove(&oldest.identity);
            }
        }
    }
}

pub fn identity_of(username: &str) -> &str {
    username.split('.').next().unwrap_or(username)
}

pub fn window_for_difficulty(network_difficulty: f64, multiple: f64, floor: u128) -> u128 {
    let w = network_difficulty * multiple;
    let scaled = if w.is_finite() && w >= 1.0 { w as u128 } else { 1 };
    scaled.max(floor.max(1))
}
