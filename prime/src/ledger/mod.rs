//! The pool's record of the shares it credited: the payout window it keeps in memory and
//! the blocks and owed amounts it has found. The redb file behind it is in `store`.

mod store;

use std::collections::{HashMap, VecDeque};
use std::io;
use std::path::Path;
use store::Store;

/// The most shares the payout window holds, whatever work they sum to.
pub(crate) const MAX_SHARES: usize = 1 << 20;

pub const SHARES_PER_KEEP_UNIT: u64 = MAX_SHARES as u64;

pub(crate) const HASH_SIZE: usize = ratum::bitcoin::HASH_SIZE;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    pub at: u64,
    pub identity: String,
    pub difficulty: u64,
    pub hash: Option<[u8; 32]>,
    pub tag: String,
}

/// What opening a ledger found in it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadBack {
    pub skipped: usize,
    pub truncated: bool,
    pub stamped: bool,
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
        Self {
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
        let mut ledger = Self::new(window);
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
        if let Some(store) = &self.store {
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
        if let Some(store) = &self.store
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
        if let Some(store) = &self.store {
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
        if let Some(store) = &self.store {
            store.write_owed(&owed)?;
        }
        self.owed[index] = owed.clone();
        Ok(Some(owed))
    }

    pub fn void_owed(&mut self, hash: &[u8; 32]) -> io::Result<Option<OwedBlock>> {
        let Some(index) = self.owed.iter().position(|o| o.block_hash == *hash) else {
            return Ok(None);
        };
        if let Some(store) = &self.store {
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
        if count_trimmed && !self.count_capped {
            log::warn!(
                "the share window is capped at {MAX_SHARES} shares, which hold less work than \
                 the configured window times network difficulty; miners are paid over the \
                 newest {MAX_SHARES} shares. Raise the assigned share difficulty to cover the \
                 intended span."
            );
        }
        self.count_capped = count_trimmed;
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
