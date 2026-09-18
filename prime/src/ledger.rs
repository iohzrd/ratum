//! The share window: the newest shares whose difficulty totals the window's work, and the work each
//! identity holds in it. The window is sized to the network difficulty and is what a block's value
//! is divided by.

pub mod blocks;
mod db;
pub mod split;
mod store;
#[cfg(test)]
mod tests;

use crate::accounting::{ACCEPTED_HASH_RETENTION_SECS, MAX_ACCEPTED_HASHES};
use blocks::BlockRecords;
use log::{info, warn};
use ratum::rpc;
use split::SplitPolicy;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use store::{Store, WindowRow};

/// The most shares the window holds whatever their difficulties sum to. The window is a work
/// target, and how many shares that is depends on their difficulty, so a count bound is the
/// only memory guarantee that does not depend on an assigned difficulty being reasonable. The
/// pool is not meant to reach it in normal operation: `--min-diff` is what keeps the count
/// below it, since the window requires at most `--window` times the network difficulty divided
/// by `--min-diff` shares. Reaching this bound ends the window at the newest `MAX_SHARES`
/// shares, spanning less work than `--window` specifies. A share costs 16 bytes in the window
/// and an identity with a share in it about 260 more (both measured), so `2^22` is 64 MiB for
/// a pool of a few dozen miners and about 1.1 GiB if every share came from a different
/// address; a widening reload holds the previous window beside the new one, twice either.
pub const MAX_SHARES: usize = 1 << 22;

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
/// entry exists while the identity has a share in the window.
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

// An identity is held only while a share in the window credits it, so there are at most
// `MAX_SHARES + 1` (a share is pushed before the window is trimmed), indexed up to
// `MAX_SHARES`, and `WindowShare::credit` shifts the index left one bit into a `u32`.
const _: () = assert!(MAX_SHARES < 1 << 31);

/// One share in the window, as much of it as the window reads: its work, its acceptance time for
/// the hashrate, and the identity it credits with whether it counts as own-gateway work. The
/// block hash, the identity's name and the tag stay in the ledger file. 16 bytes.
#[derive(Clone, Copy, Debug)]
struct WindowShare {
    difficulty: u64,
    /// Seconds since the Unix epoch; `u32` holds them until 2106.
    accepted_at: u32,
    /// The identity's index in `Identities`, shifted left one bit, with the low bit set when
    /// the share is own-gateway work.
    credit: u32,
}

impl WindowShare {
    fn new(share: &Share, identity: u32, own_gateway: bool) -> Self {
        Self {
            difficulty: share.difficulty,
            accepted_at: u32::try_from(share.accepted_at).unwrap_or(u32::MAX),
            credit: identity << 1 | u32::from(own_gateway),
        }
    }

    fn identity(self) -> u32 {
        self.credit >> 1
    }

    fn own_gateway(self) -> bool {
        self.credit & 1 == 1
    }

    fn work(self) -> u128 {
        u128::from(self.difficulty)
    }
}

/// The identities with a share in the window, each under the index its shares refer to. An
/// index is released when the last share referring to it leaves the window, and reused.
#[derive(Debug, Default)]
struct Identities {
    /// Each name once, shared with its entry.
    by_name: HashMap<Arc<str>, u32>,
    entries: Vec<Option<IdentityEntry>>,
    free: Vec<u32>,
}

#[derive(Debug)]
struct IdentityEntry {
    name: Arc<str>,
    state: IdentityState,
    /// The shares in the window crediting this identity; the index is released at zero.
    shares: u32,
}

impl Identities {
    /// The index of `name`, taking a released one or a new one for an identity not held.
    fn index_of(&mut self, name: &str) -> u32 {
        if let Some(&i) = self.by_name.get(name) {
            return i;
        }
        let name: Arc<str> = Arc::from(name);
        let entry =
            IdentityEntry { name: Arc::clone(&name), state: IdentityState::default(), shares: 0 };
        let i = match self.free.pop() {
            Some(i) => {
                self.entries[i as usize] = Some(entry);
                i
            }
            None => {
                self.entries.push(Some(entry));
                u32::try_from(self.entries.len() - 1).expect("at most MAX_SHARES + 1 identities")
            }
        };
        self.by_name.insert(name, i);
        i
    }

    fn entry_mut(&mut self, i: u32) -> &mut IdentityEntry {
        self.entries[i as usize].as_mut().expect("a share in the window refers to it")
    }

    fn name(&self, i: u32) -> &str {
        &self.entries[i as usize].as_ref().expect("a share in the window refers to it").name
    }

    fn release(&mut self, i: u32) {
        if let Some(entry) = self.entries[i as usize].take() {
            self.by_name.remove(&entry.name);
            self.free.push(i);
        }
    }

    fn iter(&self) -> impl Iterator<Item = (&str, &IdentityState)> {
        self.entries.iter().flatten().map(|e| (&*e.name, &e.state))
    }

    fn len(&self) -> usize {
        self.by_name.len()
    }
}

pub struct Ledger {
    shares: VecDeque<WindowShare>,
    identities: Identities,
    window_rule: WindowRule,
    split_policy: SplitPolicy,
    total_work: u128,
    window: u128,
    store: Option<Store>,
    cumulative_work: u128,
    /// `MAX_SHARES` outside tests, which exercise the bound at a size they can reach.
    max_shares: usize,
    count_capped: bool,
    /// The network difficulty last passed to `set_network_difficulty`, in the node's unit:
    /// that of the block being mined, which is what the window is sized to.
    network_difficulty: Option<f64>,
    /// Set when a widening re-read of the store failed: the window is at its new size but holds
    /// only the shares of the narrower one, so the next `set_network_difficulty` re-reads even
    /// when the size it computes is the one already set.
    refill_pending: bool,
}

impl Ledger {
    /// An empty file-less ledger, its window at the rule's floor. A share whose secondary tag
    /// is not the public gateway's counts as own-gateway work; with no public gateway, no share
    /// does.
    pub fn new(window_rule: WindowRule, split_policy: SplitPolicy) -> Self {
        Self {
            shares: VecDeque::new(),
            identities: Identities::default(),
            window: window_rule.floor.max(1),
            window_rule,
            split_policy,
            total_work: 0,
            store: None,
            cumulative_work: 0,
            max_shares: MAX_SHARES,
            count_capped: false,
            network_difficulty: None,
            refill_pending: false,
        }
    }

    /// Reads the store's share window back into this empty ledger, which records every later
    /// share to the store.
    fn attach(&mut self, store: Store) -> io::Result<ReadBack> {
        let mut read_back = self.load(&store)?;
        read_back.stamped = store.stamped;
        self.cumulative_work = store.cumulative_work;
        self.store = Some(store);
        Ok(read_back)
    }

    /// Replaces the window with the store's newest shares whose work reaches it, streamed
    /// from the file oldest first. A read that fails part way leaves the window as it was.
    fn load(&mut self, store: &Store) -> io::Result<ReadBack> {
        let (window, max_shares) = (self.window, self.max_shares);
        self.load_from(|push| store.read_window(window, max_shares, push))
    }

    /// `load` with the read passed in: `read` gives the function it is called with the number
    /// of shares, then each share. The previous window is held until the read succeeds, so a
    /// reload briefly holds two windows, the new one allocated once at its size. A read that
    /// succeeds with no shares leaves the window empty and not count capped.
    fn load_from(
        &mut self,
        read: impl FnOnce(&mut dyn FnMut(WindowRow)) -> io::Result<ReadBack>,
    ) -> io::Result<ReadBack> {
        let held = (
            std::mem::take(&mut self.shares),
            std::mem::take(&mut self.identities),
            std::mem::replace(&mut self.total_work, 0),
            self.count_capped,
        );
        let loaded = read(&mut |row| match row {
            // One slot over the count: a recorded share is pushed before the oldest is trimmed.
            WindowRow::Count(n) => self.shares.reserve_exact(n + 1),
            WindowRow::Share(share) => {
                self.push(&share);
                self.trim();
            }
        });
        match &loaded {
            Ok(_) => self.count_capped = self.is_count_capped(),
            Err(_) => (self.shares, self.identities, self.total_work, self.count_capped) = held,
        }
        loaded
    }

    /// Sizes the window to `network_difficulty` by the window rule and returns how many
    /// shares widening it re-read from the store. A widening whose re-read failed is re-read
    /// at the next call, whatever size that call computes.
    pub fn set_network_difficulty(&mut self, network_difficulty: f64) -> usize {
        self.network_difficulty = Some(network_difficulty);
        let window = self.window_rule.window_for(network_difficulty);
        if window == self.window && !self.refill_pending {
            return 0;
        }
        self.set_window(window)
    }

    /// The network difficulty the window was last sized to, in the node's unit; none before
    /// the first `set_network_difficulty`.
    pub fn network_difficulty(&self) -> Option<f64> {
        self.network_difficulty
    }

    fn set_window(&mut self, window: u128) -> usize {
        let window = window.max(1);
        let widened = window > self.window || self.refill_pending;
        self.window = window;
        let re_read = if widened { self.refill() } else { 0 };
        self.trim();
        re_read
    }

    /// Re-reads the window from the store after a widening. On a failed read the shares held
    /// stay as they were, which span less than the window, and `refill_pending` is set so the
    /// read is tried again.
    fn refill(&mut self) -> usize {
        let Some(store) = self.store.take() else { return 0 };
        let before = self.shares.len();
        let loaded = self.load(&store);
        self.store = Some(store);
        self.refill_pending = loaded.is_err();
        match loaded {
            Ok(read_back) => {
                if read_back.truncated {
                    warn!(
                        "the wider share window exceeds the retained ledger; work older than \
                         that is not credited (raise --ledger-keep-shares to keep it)"
                    );
                }
                self.shares.len().saturating_sub(before)
            }
            Err(e) => {
                warn!(
                    "could not re-read the ledger to widen the share window ({e}); it holds the \
                     shares of the narrower window until the next time the node's difficulty \
                     is read, when the read is retried"
                );
                0
            }
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

    pub fn max_shares(&self) -> usize {
        self.max_shares
    }

    /// Whether the newest `max_shares` shares hold less work than the window, so the count
    /// bound, not the work the window asks for, is what ends the payout set.
    pub fn count_capped(&self) -> bool {
        self.count_capped
    }

    /// Exercises the count bound at a size a test can reach.
    #[cfg(test)]
    pub fn set_max_shares(&mut self, max_shares: usize) {
        self.max_shares = max_shares.max(1);
        self.trim();
    }

    pub fn len(&self) -> usize {
        self.shares.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.shares.is_empty()
    }

    /// The acceptance time of every share in the window, oldest first: which shares it holds.
    #[cfg(test)]
    pub fn accepted_times(&self) -> Vec<u64> {
        self.shares.iter().map(|s| u64::from(s.accepted_at)).collect()
    }

    /// The acceptance time and block hash of the stored shares accepted at or after `cutoff`,
    /// at most `max`, oldest first; none for a file-less ledger, which starts empty.
    pub fn accepted_since(&self, cutoff: u64, max: usize) -> io::Result<Vec<(u64, [u8; 32])>> {
        match &self.store {
            Some(store) => store.accepted_since(cutoff, max),
            None => Ok(Vec::new()),
        }
    }

    /// Records the share and returns how many stored shares `--ledger-keep-shares` retention
    /// removed. A duplicate is refused before it reaches the ledger (`accounting::claim`).
    pub fn record(&mut self, share: Share) -> io::Result<usize> {
        let keep_after = share.accepted_at.saturating_sub(ACCEPTED_HASH_RETENTION_SECS);
        let cumulative_work = self.cumulative_work + u128::from(share.difficulty);
        if let Some(store) = &mut self.store {
            store.insert(&share, cumulative_work)?;
        }
        self.cumulative_work = cumulative_work;
        self.push(&share);
        self.trim();
        let Some(store) = &self.store else { return Ok(0) };
        let retained = store.retain(self.shares.len() as u64, keep_after, MAX_ACCEPTED_HASHES);
        Ok(retained.unwrap_or_else(|e| {
            warn!("ledger retention failed; the share is recorded ({e})");
            0
        }))
    }

    pub fn cumulative_work(&self) -> u128 {
        self.cumulative_work
    }

    /// The shares accepted at or after `cutoff`, newest first.
    fn shares_since(&self, cutoff: u64) -> impl Iterator<Item = &WindowShare> {
        self.shares.iter().rev().take_while(move |s| u64::from(s.accepted_at) >= cutoff)
    }

    /// The work of the shares accepted at or after `cutoff`.
    pub fn work_since(&self, cutoff: u64) -> u128 {
        self.shares_since(cutoff).map(|s| s.work()).sum()
    }

    /// The work of the shares accepted at or after `cutoff`, by identity. The hashrate
    /// sampler wants the total alone, so it calls `work_since` and allocates nothing.
    pub fn work_since_by_identity(&self, cutoff: u64) -> HashMap<String, u128> {
        let mut by_index: HashMap<u32, u128> = HashMap::new();
        for s in self.shares_since(cutoff) {
            *by_index.entry(s.identity()).or_insert(0) += s.work();
        }
        by_index.into_iter().map(|(i, work)| (self.identities.name(i).to_string(), work)).collect()
    }

    /// Every identity with work in the window and its state, most work first.
    pub fn identities(&self) -> Vec<(String, IdentityState)> {
        let mut v: Vec<(String, IdentityState)> =
            self.identities.iter().map(|(id, state)| (id.to_string(), state.clone())).collect();
        v.sort_by(|(a, x), (b, y)| most_work_first((a, x.work), (b, y.work)));
        v
    }

    fn push(&mut self, share: &Share) {
        let own = self.is_own_gateway_share(share);
        let index = self.identities.index_of(&share.identity);
        let entry = self.identities.entry_mut(index);
        let work = u128::from(share.difficulty);
        entry.state.work += work;
        if own {
            entry.state.own_gateway_work += work;
        }
        entry.state.tag_secondary.clone_from(&share.tag_secondary);
        entry.shares += 1;
        self.total_work += work;
        let len = self.shares.len();
        if len == self.shares.capacity() {
            // Grown here rather than by `push_back`, which doubles: by an eighth, so the buffer
            // stays within an eighth of the most shares the window has held, and never past
            // `max_shares + 1`, the most it holds since a share is pushed before the oldest is
            // trimmed.
            let room = (self.max_shares + 1).saturating_sub(len);
            self.shares.reserve_exact((len / 8).min(room).max(1));
        }
        self.shares.push_back(WindowShare::new(share, index, own));
    }

    fn trim(&mut self) {
        while self.shares.len() > 1 && self.total_work > self.window {
            let over = self.total_work - self.window;
            let oldest = self.shares.front().expect("non-empty");
            if oldest.work() > over {
                break;
            }
            self.drop_oldest();
        }
        while self.shares.len() > self.max_shares {
            self.drop_oldest();
        }
        let capped = self.is_count_capped();
        if capped && !self.count_capped {
            warn!(
                "the share window is capped at {0} shares, which hold less work than the \
                 configured window times network difficulty; miners are paid over the newest \
                 {0} shares. Raise --min-diff so the window requires fewer shares to span \
                 the configured work.",
                self.max_shares
            );
        }
        self.count_capped = capped;
    }

    /// Whether the window holds `max_shares` shares with less work than it asks for.
    fn is_count_capped(&self) -> bool {
        self.shares.len() >= self.max_shares && self.total_work < self.window
    }

    fn drop_oldest(&mut self) {
        let Some(oldest) = self.shares.pop_front() else { return };
        let work = oldest.work();
        self.total_work -= work;
        let index = oldest.identity();
        let entry = self.identities.entry_mut(index);
        entry.state.work -= work;
        if oldest.own_gateway() {
            entry.state.own_gateway_work -= work;
        }
        entry.shares -= 1;
        if entry.shares == 0 {
            self.identities.release(index);
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

    /// The ledger file a ledger command reads, which must exist: the command opens it and
    /// never creates one.
    pub fn existing_file(&self, flag: &str) -> io::Result<PathBuf> {
        Ok(match self {
            Self::File(p) if p.is_file() => p.clone(),
            Self::File(p) => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "no ledger file at {}; {flag} reads the ledger a pool wrote and does not \
                         create one",
                        p.display()
                    ),
                ));
            }
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

/// Passes `f` every share the existing ledger file stores, oldest first and one at a time, so
/// a ledger larger than memory can be read; one read transaction, without reading back the
/// share window or opening the block records. Stops at the first error `f` returns.
pub fn dump_file(path: &Path, f: impl FnMut(Share) -> io::Result<()>) -> io::Result<()> {
    store::dump_file(path, f)
}

/// `ledger` with the store at `path` attached, and the block records stored beside it; with
/// no path, `ledger` stays file-less.
pub fn open_share_ledger(
    path: Option<&Path>,
    keep: Option<u64>,
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
             (raise --ledger-keep-shares to keep it)",
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
            "keeping at most {n} of the most recent shares in {}, and never fewer than the \
             window holds or than were accepted in the last {} seconds (at most {})",
            path.display(),
            ACCEPTED_HASH_RETENTION_SECS,
            MAX_ACCEPTED_HASHES
        ),
        None => info!("every share in {} is kept", path.display()),
    }
    Ok((ledger, records))
}
