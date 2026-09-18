//! The share window: the newest shares whose difficulty totals the window's work, and the work each
//! identity holds in it. The window is sized to the network difficulty and is what a block's value
//! is divided by.

pub mod blocks;
mod db;
pub mod split;
mod store;
#[cfg(test)]
mod tests;

use blocks::BlockRecords;
use log::{info, warn};
use ratum::rpc;
use split::SplitPolicy;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use store::Store;

pub const MAX_SHARES: usize = 1 << 20;
pub const SHARES_PER_KEEP_UNIT: u64 = MAX_SHARES as u64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    pub accepted_at: u64,
    pub identity: String,
    pub difficulty: u64,
    pub block_hash: [u8; 32],
    pub tag_secondary: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadBack {
    pub skipped: usize,
    pub truncated: bool,
    pub stamped: bool,
}

/// What the window holds for one identity: its work, the part of it from shares carrying
/// a secondary tag other than the public gateway's, and the tag of its newest share. An
/// entry exists while the identity has work in the window.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdentityState {
    pub work: u128,
    pub own_gateway_work: u128,
    pub tag_secondary: String,
}

/// The work the share window spans: `multiple` times the network difficulty, never under
/// `floor`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct WindowRule {
    pub multiple: f64,
    pub floor: u128,
}

impl WindowRule {
    /// A window of `window` work at every network difficulty.
    #[cfg(test)]
    pub fn fixed(window: u128) -> Self {
        Self { multiple: 0.0, floor: window }
    }

    pub fn window_for(&self, network_difficulty: f64) -> u128 {
        let w = network_difficulty * self.multiple;
        let scaled = if w.is_finite() && w >= 1.0 { w as u128 } else { 1 };
        scaled.max(self.floor.max(1))
    }
}

pub struct Ledger {
    shares: VecDeque<Share>,
    identities: HashMap<String, IdentityState>,
    window_rule: WindowRule,
    split_policy: SplitPolicy,
    total_work: u128,
    window: u128,
    store: Option<Store>,
    cumulative_work: u128,
    count_capped: bool,
}

impl Ledger {
    /// An empty file-less ledger, its window at the rule's floor. A share whose secondary tag
    /// is not the public gateway's counts as own-gateway work; with no public gateway, no share
    /// does.
    pub fn new(window_rule: WindowRule, split_policy: SplitPolicy) -> Self {
        Self {
            shares: VecDeque::new(),
            identities: HashMap::new(),
            window: window_rule.floor.max(1),
            window_rule,
            split_policy,
            total_work: 0,
            store: None,
            cumulative_work: 0,
            count_capped: false,
        }
    }

    /// Reads the store's share window back into this empty ledger, which records every later
    /// share to the store.
    fn attach(&mut self, store: Store) -> io::Result<ReadBack> {
        let (shares, mut read_back) = store.read_back(self.window)?;
        read_back.stamped = store.stamped;
        self.fill(shares);
        self.cumulative_work = store.cumulative_work;
        self.store = Some(store);
        Ok(read_back)
    }

    /// Sizes the window to `network_difficulty` by the window rule and returns how many
    /// shares widening it re-read from the store.
    pub fn set_network_difficulty(&mut self, network_difficulty: f64) -> usize {
        let window = self.window_rule.window_for(network_difficulty);
        if window == self.window {
            return 0;
        }
        self.set_window(window)
    }

    fn set_window(&mut self, window: u128) -> usize {
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
                    warn!("could not re-read the ledger to widen the share window: {e}");
                    return 0;
                }
            },
            None => return 0,
        };
        if read_back.truncated {
            warn!(
                "the wider share window exceeds the retained ledger; work older than \
                 that is not credited (raise --ledger-keep to keep it)"
            );
        }
        self.fill(shares);
        self.shares.len().saturating_sub(before)
    }

    fn fill(&mut self, shares: Vec<Share>) {
        self.shares.clear();
        self.identities.clear();
        self.total_work = 0;
        for share in shares {
            self.push(share);
            self.trim();
        }
    }

    pub fn window_rule(&self) -> WindowRule {
        self.window_rule
    }

    pub fn split_policy(&self) -> &SplitPolicy {
        &self.split_policy
    }

    fn is_own_gateway_share(&self, share: &Share) -> bool {
        let public = self.split_policy.public_gateway.as_ref();
        public.is_some_and(|public| share.tag_secondary != public.tag)
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

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.shares.is_empty()
    }

    pub fn block_hashes(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.shares.iter().map(|s| &s.block_hash)
    }

    /// Records the share and returns how many stored shares `--ledger-keep` retention
    /// removed. A duplicate is refused before it reaches the ledger (`accounting::claim`).
    pub fn record(&mut self, share: Share) -> io::Result<usize> {
        let cumulative_work = self.cumulative_work + u128::from(share.difficulty);
        if let Some(store) = &mut self.store {
            store.insert(&share, cumulative_work)?;
        }
        self.cumulative_work = cumulative_work;
        self.push(share);
        self.trim();
        let Some(store) = &self.store else { return Ok(0) };
        Ok(store.retain().unwrap_or_else(|e| {
            warn!("ledger retention failed; the share is recorded ({e})");
            0
        }))
    }

    pub fn cumulative_work(&self) -> u128 {
        self.cumulative_work
    }

    /// The shares accepted at or after `cutoff`, newest first.
    fn shares_since(&self, cutoff: u64) -> impl Iterator<Item = &Share> {
        self.shares.iter().rev().take_while(move |s| s.accepted_at >= cutoff)
    }

    /// The work of the shares accepted at or after `cutoff`.
    pub fn work_since(&self, cutoff: u64) -> u128 {
        self.shares_since(cutoff).map(|s| u128::from(s.difficulty)).sum()
    }

    /// The work of the shares accepted at or after `cutoff`, by identity. The hashrate
    /// sampler wants the total alone, so it calls `work_since` and allocates nothing.
    pub fn work_since_by_identity(&self, cutoff: u64) -> HashMap<String, u128> {
        let mut by_identity: HashMap<String, u128> = HashMap::new();
        for s in self.shares_since(cutoff) {
            *by_identity.entry(s.identity.clone()).or_insert(0) += u128::from(s.difficulty);
        }
        by_identity
    }

    /// Every identity with work in the window and its state, most work first.
    pub fn identities(&self) -> Vec<(String, IdentityState)> {
        let mut v: Vec<(String, IdentityState)> =
            self.identities.iter().map(|(id, state)| (id.clone(), state.clone())).collect();
        v.sort_by(|(a, x), (b, y)| most_work_first((a, x.work), (b, y.work)));
        v
    }

    fn push(&mut self, share: Share) {
        self.total_work += u128::from(share.difficulty);
        let own = self.is_own_gateway_share(&share);
        let state = self.identities.entry(share.identity.clone()).or_default();
        state.work += u128::from(share.difficulty);
        if own {
            state.own_gateway_work += u128::from(share.difficulty);
        }
        state.tag_secondary.clone_from(&share.tag_secondary);
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
            warn!(
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
        let own = self.is_own_gateway_share(&oldest);
        let Some(state) = self.identities.get_mut(&oldest.identity) else { return };
        state.work -= u128::from(oldest.difficulty);
        if own {
            state.own_gateway_work -= u128::from(oldest.difficulty);
        }
        if state.work == 0 {
            self.identities.remove(&oldest.identity);
        }
    }
}

/// Most work first; identities with equal work in name order, so a split is the same
/// whatever order the map yields them in.
fn most_work_first((a, a_work): (&str, u128), (b, b_work): (&str, u128)) -> std::cmp::Ordering {
    b_work.cmp(&a_work).then_with(|| a.cmp(b))
}

pub enum LedgerLocation {
    File(PathBuf),
    InDir(PathBuf),
    MemoryOnly,
}

impl LedgerLocation {
    pub fn new(ledger_path: Option<String>, data_dir: Option<&Path>) -> Self {
        match (ledger_path, data_dir) {
            (Some(p), _) => Self::File(PathBuf::from(p)),
            (None, Some(dir)) => Self::InDir(dir.to_path_buf()),
            (None, None) => Self::MemoryOnly,
        }
    }

    /// The ledger file for the chain, or none for a memory-only ledger.
    pub fn file_for(&self, chain: Option<rpc::Chain>) -> io::Result<Option<PathBuf>> {
        Ok(match (self, chain) {
            (Self::File(p), _) => Some(p.clone()),
            (Self::InDir(dir), Some(rpc::Chain::Other)) => {
                return Err(invalid_input(format!(
                    "the node reports a chain this pool has no name for, so it cannot name the \
                     ledger in {}; give --ledger a file for it",
                    dir.display()
                )));
            }
            (Self::InDir(dir), Some(c)) => Some(dir.join(format!("{}.redb", c.name()))),
            (Self::InDir(_), None) => {
                unreachable!("a data directory waits for the chain")
            }
            (Self::MemoryOnly, _) => None,
        })
    }

    pub fn existing_file(&self, flag: &str) -> io::Result<PathBuf> {
        Ok(match self {
            Self::File(p) => p.clone(),
            Self::InDir(dir) => match ledger_files_in(dir)?.as_slice() {
                [one] => one.clone(),
                [] => {
                    return Err(invalid_input(format!("no ledger (*.redb) in {}", dir.display())));
                }
                many => {
                    let names: Vec<String> = many.iter().map(|p| p.display().to_string()).collect();
                    return Err(invalid_input(format!(
                        "{} holds more than one ledger; give --ledger to choose one of: {}",
                        dir.display(),
                        names.join(", ")
                    )));
                }
            },
            Self::MemoryOnly => {
                return Err(invalid_input(format!(
                    "{flag} needs a ledger: give --ledger or --data-dir"
                )));
            }
        })
    }
}

fn invalid_input(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn ledger_files_in(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "redb"))
        .collect();
    found.sort();
    Ok(found)
}

/// Every share the existing ledger file stores, oldest first, read in one read transaction
/// without reading back the share window or opening the block records.
pub fn dump_file(path: &Path) -> io::Result<Vec<Share>> {
    store::dump_file(path)
}

/// `ledger` with the store at `path` attached, and the block records stored beside it; with
/// no path, `ledger` stays file-less.
pub fn open_share_ledger(
    path: Option<&Path>,
    keep: Option<usize>,
    chain_name: Option<&str>,
    mut ledger: Ledger,
) -> io::Result<(Ledger, BlockRecords)> {
    let Some(path) = path else {
        warn!(
            "no --ledger file or --data-dir; the share window and the block records are lost on \
             restart"
        );
        return Ok((ledger, BlockRecords::default()));
    };
    let store = Store::open(path, keep, chain_name)?;
    let records = BlockRecords::open(store.database())?;
    let read_back = ledger.attach(store)?;
    if read_back.stamped {
        info!(
            "{} carried no chain stamp and is now stamped {}",
            path.display(),
            chain_name.unwrap_or("?")
        );
    }
    if read_back.skipped != 0 {
        warn!("{} unreadable rows in {} were skipped", read_back.skipped, path.display());
    }
    if read_back.truncated {
        warn!(
            "the share window exceeds the retained ledger in {}: older work is not credited \
             (raise --ledger-keep to keep it)",
            path.display()
        );
    }
    info!(
        "share window from {}: {} shares, {} work",
        path.display(),
        ledger.len(),
        ledger.total_work()
    );
    match keep {
        Some(n) => info!(
            "keeping at most {} of the most recent shares in {}",
            n as u64 * SHARES_PER_KEEP_UNIT,
            path.display()
        ),
        None => info!("every share in {} is kept", path.display()),
    }
    Ok((ledger, records))
}
