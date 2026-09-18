//! The blocks the pool accepted, what their coinbases left owed to miners, and the node's last
//! confirmation reading of each.

use super::db::{DbResult as _, NAME_SEPARATOR, open_database, split_at_separator, write};
use super::split::Payout;
use bytes::BufMut as _;
use log::warn;
use ratum::bitcoin::HASH_SIZE;
use ratum::reader::ByteReader;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::Arc;

const BLOCKS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blocks");
const OWED: TableDefinition<&[u8], &[u8]> = TableDefinition::new("owed");
const CHAIN_STATE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("chain_state");

const OWED_PREFIX_LEN: usize =
    size_of::<u64>() + size_of::<u32>() + 2 * size_of::<u64>() + size_of::<u16>();
const OWED_ENTRY_PREFIX_LEN: usize = size_of::<u16>() + size_of::<u64>();
const BLOCK_PREFIX_LEN: usize =
    size_of::<u64>() + size_of::<u32>() + 3 * size_of::<u64>() + size_of::<u128>();
const CONFIRMATION_READING_LEN: usize = size_of::<u64>() + size_of::<i64>();

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwedBlock {
    pub found_at: u64,
    pub height: u32,
    pub block_hash: [u8; 32],
    pub settled_at: Option<u64>,
    pub entries: Vec<Payout>,
}

impl OwedBlock {
    pub fn total(&self) -> u64 {
        self.entries.iter().map(|p| p.sats).sum()
    }
}

/// The node's answer for one block at `checked_at`: its `getblockheader` confirmation count,
/// or `NOT_STORED` when the node stores no block under the hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfirmationReading {
    pub checked_at: u64,
    pub confirmations: i64,
}

impl ConfirmationReading {
    /// The count recorded when the node answers that it stores no block under the hash. The
    /// node answers -1 for a block it stores off its best chain and never a count this low, so
    /// the two stay distinct in the stored row, whose layout is unchanged. Negative, so
    /// `on_best_chain` is false for it.
    pub const NOT_STORED: i64 = i64::MIN;

    pub fn on_best_chain(&self) -> bool {
        ratum::rpc::on_best_chain(self.confirmations)
    }

    /// Whether the node stored the block when it was read: false for `NOT_STORED`.
    pub fn node_stores_block(&self) -> bool {
        self.confirmations != Self::NOT_STORED
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct FoundBlock {
    pub found_at: u64,
    pub height: u32,
    pub block_hash: [u8; 32],
    pub paid_to_split: u64,
    pub paid_to_pool: u64,
    pub finder: String,
    pub tag_secondary: String,
    pub network_difficulty: f64,
    pub cumulative_work: u128,
}

/// The blocks the pool accepted, what their coinbases left owed, and the node's last
/// confirmation reading of each. They are stored in the ledger file beside the shares and
/// read without them, so a ledger command does not read the share window.
#[derive(Default)]
pub struct BlockRecords {
    db: Option<Arc<Database>>,
    blocks: Vec<FoundBlock>,
    owed: Vec<OwedBlock>,
    confirmations: HashMap<[u8; HASH_SIZE], ConfirmationReading>,
}

/// What `BlockRecords::void_block` removed: the block's record and its owed record, either
/// absent when there was none.
#[derive(Debug, Default, PartialEq)]
pub struct Voided {
    pub block: Option<FoundBlock>,
    pub owed: Option<OwedBlock>,
}

impl BlockRecords {
    /// The records in the ledger file at `path`, which must exist: a ledger command reads a
    /// ledger the pool wrote and never creates one.
    pub fn open_file(path: &Path) -> io::Result<Self> {
        Self::open(Arc::new(open_database(path)?))
    }

    pub(super) fn open(db: Arc<Database>) -> io::Result<Self> {
        write(&db, |w| {
            w.open_table(BLOCKS).db()?;
            w.open_table(OWED).db()?;
            w.open_table(CHAIN_STATE).db()?;
            Ok(())
        })?;
        let mut blocks = read_packed(&db, BLOCKS, "a block", unpack_block)?;
        blocks.sort_by_key(|b| (b.found_at, b.height));
        let mut owed = read_packed(&db, OWED, "an owed", unpack_owed)?;
        owed.sort_by_key(|o| (o.found_at, o.height));
        let confirmations =
            read_packed(&db, CHAIN_STATE, "a confirmation reading", unpack_confirmations)?
                .into_iter()
                .collect();
        Ok(Self { db: Some(db), blocks, owed, confirmations })
    }

    pub fn record_block(&mut self, block: FoundBlock) -> io::Result<()> {
        if self.blocks.iter().any(|b| b.block_hash == block.block_hash) {
            return Ok(());
        }
        self.put(BLOCKS, &block.block_hash, &pack_block(&block))?;
        self.blocks.push(block);
        Ok(())
    }

    /// Writes one row, or returns without writing for a ledger with no file.
    fn put(
        &self,
        table: TableDefinition<'static, &'static [u8], &'static [u8]>,
        key: &[u8],
        value: &[u8],
    ) -> io::Result<()> {
        let Some(db) = &self.db else { return Ok(()) };
        write(db, |w| {
            w.open_table(table).db()?.insert(key, value).db()?;
            Ok(())
        })
    }

    pub fn blocks(&self) -> &[FoundBlock] {
        &self.blocks
    }

    pub fn confirmations(&self, hash: &[u8; HASH_SIZE]) -> Option<ConfirmationReading> {
        self.confirmations.get(hash).copied()
    }

    pub fn record_confirmations(
        &mut self,
        hash: [u8; HASH_SIZE],
        reading: ConfirmationReading,
    ) -> io::Result<Option<ConfirmationReading>> {
        self.put(CHAIN_STATE, &hash, &pack_confirmations(&reading))?;
        Ok(self.confirmations.insert(hash, reading))
    }

    pub fn record_owed(&mut self, owed: OwedBlock) -> io::Result<()> {
        if self.owed.iter().any(|o| o.block_hash == owed.block_hash) {
            return Ok(());
        }
        self.write_owed(&owed)?;
        self.owed.push(owed);
        Ok(())
    }

    pub fn owed(&self) -> &[OwedBlock] {
        &self.owed
    }

    pub fn settle_owed(
        &mut self,
        hash: &[u8; 32],
        settled_at: u64,
    ) -> io::Result<Option<OwedBlock>> {
        let Some(index) = self.owed.iter().position(|o| o.block_hash == *hash) else {
            return Ok(None);
        };
        if self.owed[index].settled_at.is_some() {
            return Ok(Some(self.owed[index].clone()));
        }
        let mut owed = self.owed[index].clone();
        owed.settled_at = Some(settled_at.max(1));
        self.write_owed(&owed)?;
        self.owed[index] = owed.clone();
        Ok(Some(owed))
    }

    /// Removes the block's record, its owed record and its confirmation reading in one write,
    /// whichever of them exist, and returns the two records it removed. A block off the best
    /// chain whose coinbase paid its split in full has no owed record, and is removed here so it
    /// is neither counted in luck nor read from the node again.
    pub fn void_block(&mut self, hash: &[u8; HASH_SIZE]) -> io::Result<Voided> {
        let block = self.blocks.iter().position(|b| b.block_hash == *hash);
        let owed = self.owed.iter().position(|o| o.block_hash == *hash);
        if block.is_none() && owed.is_none() && !self.confirmations.contains_key(hash) {
            return Ok(Voided::default());
        }
        if let Some(db) = &self.db {
            write(db, |w| {
                for table in [BLOCKS, OWED, CHAIN_STATE] {
                    w.open_table(table).db()?.remove(hash.as_slice()).db()?;
                }
                Ok(())
            })?;
        }
        self.confirmations.remove(hash);
        Ok(Voided {
            block: block.map(|i| self.blocks.remove(i)),
            owed: owed.map(|i| self.owed.remove(i)),
        })
    }

    fn write_owed(&self, owed: &OwedBlock) -> io::Result<()> {
        self.put(OWED, &owed.block_hash, &pack_owed(owed))
    }
}

fn read_packed<T>(
    db: &Database,
    table: TableDefinition<'static, &'static [u8], &'static [u8]>,
    what: &str,
    unpack: impl Fn(&[u8], &[u8]) -> Option<T>,
) -> io::Result<Vec<T>> {
    let r = db.begin_read().db()?;
    let table = r.open_table(table).db()?;
    let mut out = Vec::new();
    for entry in table.iter().db()? {
        let (key, value) = entry.db()?;
        match unpack(key.value(), value.value()) {
            Some(row) => out.push(row),
            None => warn!(
                "skipping {what} row ({}) that did not unpack, which an uncorrupted database \
                 never produces",
                hex::encode(key.value())
            ),
        }
    }
    Ok(out)
}

/// The total is written but never read: `unpack_owed` steps over it and sums `entries`
/// instead, and redb checksums its own pages, so it is not the row's integrity check. It
/// stays in the layout because removing it would move every field after it, and the file
/// carries no format version to migrate an existing ledger on.
fn pack_owed(o: &OwedBlock) -> Vec<u8> {
    let entries: usize = o.entries.iter().map(|p| OWED_ENTRY_PREFIX_LEN + p.identity.len()).sum();
    let mut v = Vec::with_capacity(OWED_PREFIX_LEN + entries);
    v.put_u64_le(o.found_at);
    v.put_u32_le(o.height);
    v.put_u64_le(o.total());
    v.put_u64_le(o.settled_at.unwrap_or(0));
    v.put_u16_le(o.entries.len() as u16);
    for p in &o.entries {
        v.put_u16_le(p.identity.len() as u16);
        v.put_slice(p.identity.as_bytes());
        v.put_u64_le(p.sats);
    }
    v
}

fn unpack_owed(hash: &[u8], bytes: &[u8]) -> Option<OwedBlock> {
    let block_hash: [u8; HASH_SIZE] = hash.try_into().ok()?;
    let mut c = ByteReader::new(bytes);
    let found_at = c.u64("found_at").ok()?;
    let height = c.u32("height").ok()?;
    c.advance(size_of::<u64>(), "total").ok()?;
    let settled = c.u64("settled_at").ok()?;
    let count = c.u16("entry count").ok()?;
    let mut entries = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let len = c.u16("identity length").ok()? as usize;
        let identity = String::from_utf8_lossy(c.take(len, "identity").ok()?).into_owned();
        entries.push(Payout { identity, sats: c.u64("sats").ok()? });
    }
    Some(OwedBlock {
        found_at,
        height,
        block_hash,
        settled_at: (settled != 0).then_some(settled),
        entries,
    })
}

fn pack_block(b: &FoundBlock) -> Vec<u8> {
    let mut v = Vec::with_capacity(BLOCK_PREFIX_LEN + 1 + b.finder.len() + b.tag_secondary.len());
    v.put_u64_le(b.found_at);
    v.put_u32_le(b.height);
    v.put_u64_le(b.paid_to_split);
    v.put_u64_le(b.paid_to_pool);
    v.put_f64_le(b.network_difficulty);
    v.put_u128_le(b.cumulative_work);
    v.put_slice(b.finder.as_bytes());
    v.put_u8(NAME_SEPARATOR);
    v.put_slice(b.tag_secondary.as_bytes());
    v
}

fn unpack_block(hash: &[u8], bytes: &[u8]) -> Option<FoundBlock> {
    let block_hash: [u8; HASH_SIZE] = hash.try_into().ok()?;
    let mut c = ByteReader::new(bytes);
    let found_at = c.u64("found_at").ok()?;
    let height = c.u32("height").ok()?;
    let paid_to_split = c.u64("paid_to_split").ok()?;
    let paid_to_pool = c.u64("paid_to_pool").ok()?;
    let network_difficulty = f64::from_le_bytes(c.arr("network difficulty").ok()?);
    let cumulative_work = u128::from_le_bytes(c.arr("cumulative work").ok()?);
    let (finder, tag) = split_at_separator(c.rest());
    Some(FoundBlock {
        found_at,
        height,
        block_hash,
        paid_to_split,
        paid_to_pool,
        network_difficulty,
        cumulative_work,
        finder: String::from_utf8_lossy(finder).into_owned(),
        tag_secondary: String::from_utf8_lossy(tag).into_owned(),
    })
}

fn pack_confirmations(c: &ConfirmationReading) -> Vec<u8> {
    let mut v = Vec::with_capacity(CONFIRMATION_READING_LEN);
    v.put_u64_le(c.checked_at);
    v.put_i64_le(c.confirmations);
    v
}

fn unpack_confirmations(
    hash: &[u8],
    bytes: &[u8],
) -> Option<([u8; HASH_SIZE], ConfirmationReading)> {
    let block_hash: [u8; HASH_SIZE] = hash.try_into().ok()?;
    let mut c = ByteReader::new(bytes);
    let checked_at = c.u64("checked_at").ok()?;
    let confirmations = i64::from_le_bytes(c.arr("confirmations").ok()?);
    Some((block_hash, ConfirmationReading { checked_at, confirmations }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{Scratch, found, hash, owed, payout};
    use crate::ledger::db::create_database;

    /// The records in the scratch ledger, created on the first call.
    fn open(scratch: &Scratch) -> BlockRecords {
        BlockRecords::open(create_database(&scratch.join("regtest.redb")).unwrap()).unwrap()
    }

    #[test]
    fn packs_and_unpacks_a_confirmation_reading() {
        for confirmations in [-1i64, 0, 1, 100, i64::MAX, i64::MIN] {
            let state = ConfirmationReading { checked_at: 1_750_000_000, confirmations };
            let packed = pack_confirmations(&state);
            assert_eq!(packed.len(), CONFIRMATION_READING_LEN);
            assert_eq!(unpack_confirmations(&hash(3), &packed), Some((hash(3), state)));
        }
        assert_eq!(unpack_confirmations(&hash(3), &[]), None, "a truncated row does not unpack");
        assert_eq!(
            unpack_confirmations(
                &[0u8; 4],
                &pack_confirmations(&ConfirmationReading { checked_at: 1, confirmations: 1 })
            ),
            None,
            "a key that is not a block hash does not unpack"
        );
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
            FoundBlock { tag_secondary: String::new(), ..found(4, 9) },
        ] {
            assert_eq!(unpack_block(&b.block_hash, &pack_block(&b)), Some(b));
        }
    }

    #[test]
    fn a_block_row_without_the_tag_separator_reads_back_with_an_empty_tag() {
        let b = FoundBlock { tag_secondary: String::new(), ..found(1, 48) };
        let mut bytes = pack_block(&b);
        assert_eq!(bytes.pop(), Some(0x00), "the separator is the last byte when the tag is empty");
        assert_eq!(unpack_block(&b.block_hash, &bytes), Some(b));
    }

    #[test]
    fn owed_blocks_survive_a_reopen_and_settle_once() {
        let scratch = Scratch::new("owed");
        {
            let mut r = open(&scratch);
            r.record_owed(owed(1, None)).unwrap();
            r.record_owed(owed(2, None)).unwrap();
            r.record_owed(OwedBlock { entries: vec![payout("carol", 9_999)], ..owed(1, None) })
                .unwrap();
            assert_eq!(r.owed().len(), 2);
            assert_eq!(r.owed()[0].total(), 300 + 1, "the first record stands");
        }
        let mut r = open(&scratch);
        assert_eq!(r.owed().len(), 2, "read back from the store");
        assert_eq!(r.owed()[0].entries, vec![payout("alice", 201), payout("bob", 100)]);

        let settled = r.settle_owed(&owed(1, None).block_hash, 5_000).unwrap().unwrap();
        assert_eq!(settled.settled_at, Some(5_000));
        assert_eq!(r.owed()[0].settled_at, Some(5_000), "the in-memory copy follows");
        let again = r.settle_owed(&owed(1, None).block_hash, 6_000).unwrap().unwrap();
        assert_eq!(again.settled_at, Some(5_000));
        assert!(r.settle_owed(&hash(0xdead), 6_000).unwrap().is_none());
        drop(r);

        let r = open(&scratch);
        assert_eq!(r.owed()[0].settled_at, Some(5_000), "settlement is durable");
        assert_eq!(r.owed()[1].settled_at, None);
    }

    #[test]
    fn the_confirmations_of_a_block_is_durable_and_reports_what_it_replaced() {
        let scratch = Scratch::new("chain-state");
        let on_chain = ConfirmationReading { checked_at: 1_000, confirmations: 3 };
        let orphaned = ConfirmationReading { checked_at: 2_000, confirmations: -1 };
        {
            let mut r = open(&scratch);
            assert_eq!(r.confirmations(&hash(1)), None, "nothing has been read yet");

            assert_eq!(
                r.record_confirmations(hash(1), on_chain).unwrap(),
                None,
                "the first reading"
            );
            assert_eq!(r.confirmations(&hash(1)), Some(on_chain));

            assert_eq!(
                r.record_confirmations(hash(1), orphaned).unwrap(),
                Some(on_chain),
                "the reading it replaced, which is how a block leaving the chain is reported"
            );
            assert_eq!(r.confirmations(&hash(1)), Some(orphaned));
        }
        let r = open(&scratch);
        assert_eq!(r.confirmations(&hash(1)), Some(orphaned), "the reading survives a reopen");
        assert_eq!(r.confirmations(&hash(2)), None, "and no other block gained one");
    }

    #[test]
    fn a_block_is_on_the_best_chain_at_zero_confirmations_and_not_below() {
        assert!(
            ConfirmationReading { checked_at: 1, confirmations: 0 }.on_best_chain(),
            "the tip itself"
        );
        assert!(ConfirmationReading { checked_at: 1, confirmations: 100 }.on_best_chain());
        assert!(!ConfirmationReading { checked_at: 1, confirmations: -1 }.on_best_chain());
    }

    #[test]
    fn a_voided_owed_block_is_removed_durably() {
        let scratch = Scratch::new("void");
        {
            let mut r = open(&scratch);
            r.record_owed(owed(1, None)).unwrap();
            r.record_owed(owed(2, None)).unwrap();
            let voided = r.void_block(&owed(1, None).block_hash).unwrap();
            assert_eq!(voided.owed.unwrap().total(), 300 + 1);
            assert_eq!(voided.block, None, "no block record under that hash");
            assert_eq!(r.owed().len(), 1);
            assert_eq!(r.void_block(&owed(1, None).block_hash).unwrap(), Voided::default());
        }
        let r = open(&scratch);
        assert_eq!(r.owed().len(), 1, "the removal is durable");
        assert_eq!(r.owed()[0].block_hash, owed(2, None).block_hash);

        let mut fileless = BlockRecords::default();
        fileless.record_owed(owed(3, None)).unwrap();
        assert!(fileless.void_block(&owed(3, None).block_hash).unwrap().owed.is_some());
        assert!(fileless.owed().is_empty());
    }

    /// An orphan whose coinbase paid its split in full has a block record and no owed record;
    /// voiding it removes the block, its reading and nothing of any other block.
    #[test]
    fn voiding_a_block_removes_its_record_its_owed_record_and_its_reading_durably() {
        let scratch = Scratch::new("void-block");
        let orphan = ConfirmationReading { checked_at: 7, confirmations: -1 };
        let fully_paid = found(1, 16);
        let with_owed = found(2, 32);
        let owed_for = |b: &FoundBlock| OwedBlock { block_hash: b.block_hash, ..owed(2, None) };
        {
            let mut r = open(&scratch);
            for b in [&fully_paid, &with_owed, &found(3, 48)] {
                r.record_block(b.clone()).unwrap();
                r.record_confirmations(b.block_hash, orphan).unwrap();
            }
            r.record_owed(owed_for(&with_owed)).unwrap();

            let voided = r.void_block(&fully_paid.block_hash).unwrap();
            assert_eq!(voided, Voided { block: Some(fully_paid.clone()), owed: None });
            let voided = r.void_block(&with_owed.block_hash).unwrap();
            assert_eq!(voided.block, Some(with_owed.clone()));
            assert_eq!(voided.owed, Some(owed_for(&with_owed)));
        }
        let r = open(&scratch);
        assert_eq!(r.blocks(), &[found(3, 48)], "the removals are durable");
        assert!(r.owed().is_empty());
        assert_eq!(r.confirmations(&fully_paid.block_hash), None, "the reading went with it");
        assert_eq!(r.confirmations(&with_owed.block_hash), None);
        assert_eq!(r.confirmations(&found(3, 48).block_hash), Some(orphan));
    }

    #[test]
    fn a_ledger_command_opens_an_existing_file_and_never_creates_one() {
        let scratch = Scratch::new("open-existing");
        let missing = scratch.join("missing.redb");
        assert!(BlockRecords::open_file(&missing).is_err());
        assert!(!missing.exists(), "no file is left behind");
        drop(open(&scratch));
        let r = BlockRecords::open_file(&scratch.join("regtest.redb")).unwrap();
        assert!(r.blocks().is_empty());
    }

    #[test]
    fn a_reading_that_the_node_stores_no_block_is_off_the_best_chain_and_survives_a_reopen() {
        let scratch = Scratch::new("not-stored");
        let not_stored =
            ConfirmationReading { checked_at: 9, confirmations: ConfirmationReading::NOT_STORED };
        assert!(!not_stored.on_best_chain());
        assert!(!not_stored.node_stores_block());
        let orphan = ConfirmationReading { checked_at: 9, confirmations: -1 };
        assert!(orphan.node_stores_block(), "the node stores a block off its best chain");
        open(&scratch).record_confirmations(hash(1), not_stored).unwrap();
        assert_eq!(open(&scratch).confirmations(&hash(1)), Some(not_stored));
    }

    #[test]
    fn file_less_records_track_owed_blocks_in_memory() {
        let mut r = BlockRecords::default();
        r.record_owed(owed(1, None)).unwrap();
        r.record_owed(owed(1, None)).unwrap();
        assert_eq!(r.owed().len(), 1);
        let settled = r.settle_owed(&owed(1, None).block_hash, 5_000).unwrap().unwrap();
        assert_eq!(settled.settled_at, Some(5_000));
        assert!(r.settle_owed(&hash(0xdead), 5_000).unwrap().is_none());
    }

    #[test]
    fn found_blocks_survive_a_reopen_and_a_block_is_recorded_once() {
        let scratch = Scratch::new("blocks");
        {
            let mut r = open(&scratch);
            r.record_block(found(1, 48)).unwrap();
            r.record_block(FoundBlock { paid_to_pool: 9_999, ..found(1, 48) }).unwrap();
            assert_eq!(r.blocks().len(), 1);
        }
        assert_eq!(open(&scratch).blocks(), &[found(1, 48)], "the first record is retained");

        let mut fileless = BlockRecords::default();
        fileless.record_block(found(1, 48)).unwrap();
        fileless.record_block(found(1, 48)).unwrap();
        assert_eq!(fileless.blocks().len(), 1);
    }
}
