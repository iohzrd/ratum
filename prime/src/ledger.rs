//! The share window: the newest shares whose difficulty totals the window's work, and the work each
//! identity holds in it. The window is sized to the network difficulty and is what a block's value
//! is divided by.

pub mod blocks;
mod db;
pub mod group_commit;
mod snapshot;
pub mod split;
mod store;
#[cfg(test)]
mod tests;

pub use snapshot::{snapshot_refusal, write_snapshot};

use crate::accounting::{ACCEPTED_HASH_RETENTION_SECS, MAX_ACCEPTED_HASHES};
use blocks::BlockRecords;
use log::{info, warn};
use ratum::{lock, rpc};
use redb::{Database, ReadTransaction};
use split::SplitPolicy;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
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

/// What the window holds for one identity: its work and the tag of its newest share. An
/// entry exists while the identity has a share in the window.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdentityState {
    pub work: u128,
    pub tag_secondary: String,
}

/// The work the share window spans: `multiple` times the network difficulty, at least 1.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct WindowRule {
    pub multiple: f64,
}

impl WindowRule {
    /// A window of `window` work at a network difficulty of 1, which a test leaves set.
    #[cfg(test)]
    pub fn fixed(window: u128) -> Self {
        Self { multiple: window as f64 }
    }

    pub fn window_for(&self, network_difficulty: f64) -> u128 {
        let w = network_difficulty * self.multiple;
        if w.is_finite() && w >= 1.0 { w as u128 } else { 1 }
    }
}

// An identity is held only while a share in the window credits it, so there are at most
// `MAX_SHARES + 1` (a share is pushed before the window is trimmed), indexed up to
// `MAX_SHARES` in `WindowShare::credit`, a `u32`.
const _: () = assert!(MAX_SHARES < u32::MAX as usize);

/// One share in the window, as much of it as the window reads: its work, its acceptance time for
/// the hashrate, and the identity it credits. The block hash, the identity's name and the tag
/// stay in the ledger file. 16 bytes.
#[derive(Clone, Copy, Debug)]
struct WindowShare {
    difficulty: u64,
    /// Seconds since the Unix epoch; `u32` holds them until 2106.
    accepted_at: u32,
    /// The identity's index in `Identities`.
    credit: u32,
}

impl WindowShare {
    fn new(share: &Share, identity: u32) -> Self {
        Self {
            difficulty: share.difficulty,
            accepted_at: u32::try_from(share.accepted_at).unwrap_or(u32::MAX),
            credit: identity,
        }
    }

    fn identity(self) -> u32 {
        self.credit
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

    fn iter(&self) -> impl Iterator<Item = (&Arc<str>, &IdentityState)> {
        self.entries.iter().flatten().map(|e| (&e.name, &e.state))
    }
}

/// The shares in the window, oldest first, the identities they credit and their total work.
#[derive(Debug, Default)]
struct Contents {
    shares: VecDeque<WindowShare>,
    identities: Identities,
    total_work: u128,
}

impl Contents {
    /// The contents `read` gives, trimmed to `window` work and `max_shares` shares: `read`
    /// gives the function it is called with the number of shares, then each share.
    fn read(
        window: u128,
        max_shares: usize,
        read: impl FnOnce(&mut dyn FnMut(WindowRow)) -> io::Result<ReadBack>,
    ) -> io::Result<(Self, ReadBack)> {
        let mut contents = Self::default();
        let read_back = read(&mut |row| match row {
            // One slot over the count: a recorded share is pushed before the oldest is trimmed.
            WindowRow::Count(n) => contents.shares.reserve_exact(n + 1),
            WindowRow::Share(share) => {
                contents.push(&share, max_shares);
                contents.trim(window, max_shares);
            }
        })?;
        Ok((contents, read_back))
    }

    fn push(&mut self, share: &Share, max_shares: usize) {
        let index = self.identities.index_of(&share.identity);
        let entry = self.identities.entry_mut(index);
        let work = u128::from(share.difficulty);
        entry.state.work += work;
        entry.state.tag_secondary.clone_from(&share.tag_secondary);
        entry.shares += 1;
        self.total_work += work;
        let len = self.shares.len();
        if len == self.shares.capacity() {
            // Grown here rather than by `push_back`, which doubles: by an eighth, so the buffer
            // stays within an eighth of the most shares the window has held, and never past
            // `max_shares + 1`, the most it holds since a share is pushed before the oldest is
            // trimmed.
            let room = (max_shares + 1).saturating_sub(len);
            self.shares.reserve_exact((len / 8).min(room).max(1));
        }
        self.shares.push_back(WindowShare::new(share, index));
    }

    /// Drops the oldest shares the newest no longer need to reach `window` work, then those
    /// past `max_shares`.
    fn trim(&mut self, window: u128, max_shares: usize) {
        while self.shares.len() > 1 && self.total_work > window {
            let over = self.total_work - window;
            let oldest = self.shares.front().expect("non-empty");
            if oldest.work() > over {
                break;
            }
            self.drop_oldest();
        }
        while self.shares.len() > max_shares {
            self.drop_oldest();
        }
    }

    fn drop_oldest(&mut self) {
        let Some(oldest) = self.shares.pop_front() else { return };
        let work = oldest.work();
        self.total_work -= work;
        let index = oldest.identity();
        let entry = self.identities.entry_mut(index);
        entry.state.work -= work;
        entry.shares -= 1;
        if entry.shares == 0 {
            self.identities.release(index);
        }
    }
}

/// A re-read of the store begun under the ledger lock (`Ledger::begin_reread`): the read
/// transaction it reads, and the window size and count bound it reads to.
struct Reread {
    snapshot: ReadTransaction,
    window: u128,
    max_shares: usize,
}

impl Reread {
    /// Reads the window from the snapshot; called without the ledger lock.
    fn read(&self) -> io::Result<(Contents, ReadBack)> {
        let (window, max_shares) = (self.window, self.max_shares);
        Contents::read(window, max_shares, |push| {
            store::read_window(&self.snapshot, window, max_shares, push)
        })
    }
}

/// Runs a due re-read, locking only to begin and to install it: coinbaser answers and share
/// credit use the window as it stands while it reads. Returns the shares the window gained.
pub fn reread(ledger: &Mutex<Ledger>) -> usize {
    reread_with(ledger, || {})
}

/// `reread`, calling `before_install` without the lock once the window is read.
pub fn reread_with(ledger: &Mutex<Ledger>, before_install: impl FnOnce()) -> usize {
    let Some(reread) = lock(ledger).begin_reread() else { return 0 };
    let read = reread.read();
    before_install();
    let (gained, replaced) = lock(ledger).finish_reread(reread.window, read);
    // Freed without the lock: up to `MAX_SHARES` shares and an identity for each.
    drop(replaced);
    gained
}

pub struct Ledger {
    contents: Contents,
    window_rule: WindowRule,
    split_policy: SplitPolicy,
    window: u128,
    store: Option<Store>,
    cumulative_work: u128,
    /// `MAX_SHARES` outside tests, which exercise the bound at a size they can reach.
    max_shares: usize,
    count_capped: bool,
    /// The network difficulty last passed to `set_network_difficulty`, in the node's unit:
    /// that of the block being mined, which is what the window is sized to.
    network_difficulty: Option<f64>,
    /// Set by a widening of a ledger with a store until a re-read (`reread`) installs the wider
    /// window: the window is at its new size but holds only the shares of the narrower one.
    reread_due: bool,
    /// The shares recorded since a running re-read's snapshot, which `finish_reread` adds to
    /// the window it read; none while no re-read runs.
    recorded_during_reread: Option<Vec<Share>>,
}

impl Ledger {
    /// An empty file-less ledger, its window sized to a network difficulty of 1 until one is
    /// set.
    pub fn new(window_rule: WindowRule, split_policy: SplitPolicy) -> Self {
        Self {
            contents: Contents::default(),
            window: window_rule.window_for(1.0),
            window_rule,
            split_policy,
            store: None,
            cumulative_work: 0,
            max_shares: MAX_SHARES,
            count_capped: false,
            network_difficulty: None,
            reread_due: false,
            recorded_during_reread: None,
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
        let snapshot = store.begin_read()?;
        self.load_from(|push| store::read_window(&snapshot, window, max_shares, push))
    }

    /// `load` with the read passed in: `read` gives the function it is called with the number
    /// of shares, then each share. The previous window is held until the read succeeds, so a
    /// reload briefly holds two windows, the new one allocated once at its size. A read that
    /// succeeds with no shares leaves the window empty and not count capped.
    fn load_from(
        &mut self,
        read: impl FnOnce(&mut dyn FnMut(WindowRow)) -> io::Result<ReadBack>,
    ) -> io::Result<ReadBack> {
        let (contents, read_back) = Contents::read(self.window, self.max_shares, read)?;
        self.contents = contents;
        self.trim();
        Ok(read_back)
    }

    /// Sizes the window to `network_difficulty` by the window rule; returns whether a re-read
    /// is due (`reread`). A widening leaves one due until a re-read succeeds.
    pub fn set_network_difficulty(&mut self, network_difficulty: f64) -> bool {
        self.network_difficulty = Some(network_difficulty);
        self.set_window(self.window_rule.window_for(network_difficulty))
    }

    /// The network difficulty the window was last sized to, in the node's unit; none before
    /// the first `set_network_difficulty`.
    pub fn network_difficulty(&self) -> Option<f64> {
        self.network_difficulty
    }

    fn set_window(&mut self, window: u128) -> bool {
        let window = window.max(1);
        self.reread_due |= window > self.window && self.store.is_some();
        self.window = window;
        self.trim();
        self.reread_due
    }

    /// Takes the store snapshot a due re-read reads and keeps the shares recorded from then on;
    /// none when none is due, one runs, or the snapshot fails, which leaves it due.
    fn begin_reread(&mut self) -> Option<Reread> {
        if !self.reread_due || self.recorded_during_reread.is_some() {
            return None;
        }
        let snapshot = match self.store.as_ref()?.begin_read() {
            Ok(snapshot) => snapshot,
            Err(e) => {
                warn_reread_failed(&e);
                return None;
            }
        };
        self.recorded_during_reread = Some(Vec::new());
        Some(Reread { snapshot, window: self.window, max_shares: self.max_shares })
    }

    /// Installs what a re-read read to `window` and the shares recorded since its snapshot;
    /// returns the shares gained and the contents replaced. A failed read installs nothing.
    fn finish_reread(
        &mut self,
        window: u128,
        read: io::Result<(Contents, ReadBack)>,
    ) -> (usize, Contents) {
        let recorded = self.recorded_during_reread.take().unwrap_or_default();
        let (contents, read_back) = match read {
            Ok(read) => read,
            Err(e) => {
                warn_reread_failed(&e);
                return (0, Contents::default());
            }
        };
        if read_back.truncated {
            warn!(
                "the wider share window exceeds the retained ledger; work older than that is \
                 not credited (raise --ledger-keep-shares to keep it)"
            );
        }
        let before = self.contents.shares.len();
        let replaced = std::mem::replace(&mut self.contents, contents);
        // Still due when the window widened again while the read ran.
        self.reread_due = window < self.window;
        self.trim();
        for share in &recorded {
            self.contents.push(share, self.max_shares);
            self.trim();
        }
        (self.contents.shares.len().saturating_sub(before), replaced)
    }

    pub fn window_rule(&self) -> WindowRule {
        self.window_rule
    }

    pub fn split_policy(&self) -> &SplitPolicy {
        &self.split_policy
    }

    pub fn window(&self) -> u128 {
        self.window
    }

    pub fn total_work(&self) -> u128 {
        self.contents.total_work
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
        self.contents.shares.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.contents.shares.is_empty()
    }

    /// The acceptance time of every share in the window, oldest first: which shares it holds.
    #[cfg(test)]
    pub fn accepted_times(&self) -> Vec<u64> {
        self.contents.shares.iter().map(|s| u64::from(s.accepted_at)).collect()
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
    #[cfg(test)]
    pub fn record(&mut self, share: Share) -> io::Result<usize> {
        self.record_batch(vec![share])
    }

    /// Records `shares` in order, in one store transaction (`GroupCommit` gathers them), and
    /// returns how many stored shares `--ledger-keep-shares` retention removed. The window
    /// takes them only once they are on disk: on an error none is recorded.
    pub fn record_batch(&mut self, shares: Vec<Share>) -> io::Result<usize> {
        let Some(newest) = shares.iter().map(|s| s.accepted_at).max() else { return Ok(0) };
        let keep_after = newest.saturating_sub(ACCEPTED_HASH_RETENTION_SECS);
        let cumulative_work =
            shares.iter().fold(self.cumulative_work, |work, s| work + u128::from(s.difficulty));
        if let Some(store) = &mut self.store {
            store.insert_batch(&shares, cumulative_work)?;
        }
        self.cumulative_work = cumulative_work;
        for share in &shares {
            self.contents.push(share, self.max_shares);
            self.trim();
        }
        if let Some(recorded) = &mut self.recorded_during_reread {
            // No retention until the wider window is installed: its floor, the narrower
            // window's share count, would let it remove rows the wider window holds.
            recorded.extend(shares);
            return Ok(0);
        }
        let Some(store) = &self.store else { return Ok(0) };
        let retained = store.retain(self.len() as u64, keep_after, MAX_ACCEPTED_HASHES);
        Ok(retained.unwrap_or_else(|e| {
            warn!("ledger retention failed; the shares are recorded ({e})");
            0
        }))
    }

    pub fn cumulative_work(&self) -> u128 {
        self.cumulative_work
    }

    /// The ledger file's database and path; none for a file-less ledger. A caller reads the
    /// file through its own read transaction, off the ledger lock.
    pub fn file(&self) -> Option<(Arc<Database>, PathBuf)> {
        self.store.as_ref().map(|s| (s.database(), s.path().to_path_buf()))
    }

    /// The shares accepted at or after `cutoff`, newest first.
    fn shares_since(&self, cutoff: u64) -> impl Iterator<Item = &WindowShare> {
        self.contents.shares.iter().rev().take_while(move |s| u64::from(s.accepted_at) >= cutoff)
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
        let names = &self.contents.identities;
        by_index.into_iter().map(|(i, work)| (names.name(i).to_string(), work)).collect()
    }

    /// Every identity with work in the window and its state, most work first.
    pub fn identities(&self) -> Vec<(String, IdentityState)> {
        let mut v: Vec<(String, IdentityState)> = self
            .contents
            .identities
            .iter()
            .map(|(id, state)| (id.to_string(), state.clone()))
            .collect();
        v.sort_by(|(a, x), (b, y)| most_work_first((a, x.work), (b, y.work)));
        v
    }

    fn trim(&mut self) {
        self.contents.trim(self.window, self.max_shares);
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
        self.len() >= self.max_shares && self.total_work() < self.window
    }
}

fn warn_reread_failed(e: &io::Error) {
    warn!(
        "could not re-read the ledger to widen the share window ({e}); it holds the shares of \
         the narrower window until the next time the node's difficulty is read, when the read \
         is retried"
    );
}

/// Most work first; identities with equal work in name order, so a split is the same
/// whatever order the map yields them in.
fn most_work_first((a, a_work): (&str, u128), (b, b_work): (&str, u128)) -> std::cmp::Ordering {
    b_work.cmp(&a_work).then_with(|| a.cmp(b))
}

pub enum LedgerLocation {
    InDir(PathBuf),
    MemoryOnly,
}

impl LedgerLocation {
    pub fn new(data_dir: Option<&Path>) -> Self {
        data_dir.map_or(Self::MemoryOnly, |dir| Self::InDir(dir.to_path_buf()))
    }

    /// The ledger file for the chain, or none for a memory-only ledger.
    pub fn file_for(&self, chain: Option<rpc::Chain>) -> io::Result<Option<PathBuf>> {
        Ok(match (self, chain) {
            (Self::InDir(dir), Some(rpc::Chain::Other)) => {
                return Err(invalid_input(format!(
                    "the node reports a chain this pool has no name for, so it cannot name the \
                     ledger in {}",
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
            Self::InDir(dir) => match ledger_files_in(dir)?.as_slice() {
                [one] => one.clone(),
                [] => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!(
                            "no ledger (*.redb) in {}; {flag} reads the ledger a pool wrote and \
                             does not create one",
                            dir.display()
                        ),
                    ));
                }
                many => {
                    let names: Vec<String> = many.iter().map(|p| p.display().to_string()).collect();
                    return Err(invalid_input(format!(
                        "{} holds more than one ledger; a data directory serves one chain, so \
                         move the others out: {}",
                        dir.display(),
                        names.join(", ")
                    )));
                }
            },
            Self::MemoryOnly => {
                return Err(invalid_input(format!("{flag} needs a ledger: give --data-dir")));
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

/// Passes `f` every share `db` stores, oldest first and one at a time, so a ledger larger
/// than memory can be read; one read transaction, without reading back the share window or
/// opening the block records, so the shares a running pool records meanwhile are not in its
/// view and its writes are not held up. Stops at the first error `f` returns.
pub fn dump(db: &Database, f: impl FnMut(Share) -> io::Result<()>) -> io::Result<()> {
    store::dump(db, f)
}

/// `dump` on the existing ledger file at `path`.
#[cfg(test)]
pub fn dump_file(path: &Path, f: impl FnMut(Share) -> io::Result<()>) -> io::Result<()> {
    dump(&open_existing(path)?, f)
}

/// The existing ledger file at `path`, opened writable as the pool opens it (a file a pool
/// stopped by a signal did not close is repaired only by a writable open); never created.
pub fn open_existing(path: &Path) -> io::Result<Database> {
    db::open_database(path)
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
        warn!("no --data-dir; the share window and the block records are lost on restart");
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
