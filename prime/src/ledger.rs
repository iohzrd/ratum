use std::collections::{HashMap, VecDeque};
use std::io;
use std::path::Path;

use redb::{
    Database, Durability, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
};

pub const MAX_SHARES: usize = 1 << 20;

/// The shares one unit of `--ledger-keep` retains: `--ledger-keep n` keeps at most `n` times
/// this many of the most recent shares; unset keeps every one.
pub const SHARES_PER_KEEP_UNIT: u64 = MAX_SHARES as u64;

/// The share rows, keyed by a monotonic sequence number so a range scan reads them in the
/// order they were recorded. The value is a packed `(at, difficulty, hash, identity)`.
const SHARES: TableDefinition<u64, &[u8]> = TableDefinition::new("shares");

/// A proof-of-work hash to the sequence number of the share that carries it, so a share is
/// stored once: an insert that finds the hash present is an idempotent no-op, the durable
/// complement to the in-memory `ReplayGuard`.
const BY_HASH: TableDefinition<&[u8], u64> = TableDefinition::new("by_hash");

/// Facts about the ledger as a whole. `META_CHAIN` holds the chain whose shares it records,
/// written when the ledger is created and checked on every open, so a ledger of one chain's
/// shares is never opened by a pool on another: shares recorded on a test network would
/// otherwise be paid from a mainnet coinbase.
const META: TableDefinition<&str, &str> = TableDefinition::new("meta");
const META_CHAIN: &str = "chain";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    pub at: u64,
    pub identity: String,
    pub difficulty: u64,
    pub hash: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadBack {
    /// Rows that did not unpack, which an uncorrupted database never produces.
    pub skipped: usize,
    /// Whether the window covers more work than the retained ledger holds, so some older
    /// work is not credited.
    pub truncated: bool,
    /// Whether the ledger carried no chain stamp and was stamped with the chain given on this
    /// open: a ledger written before stamps existed, adopted once.
    pub stamped: bool,
}

/// Pack a share into the row value: at (8, LE), difficulty (8, LE), hash (32), then identity.
fn pack(share: &Share) -> Vec<u8> {
    let hash = share.hash.unwrap_or([0u8; 32]);
    let mut v = Vec::with_capacity(48 + share.identity.len());
    v.extend_from_slice(&share.at.to_le_bytes());
    v.extend_from_slice(&share.difficulty.to_le_bytes());
    v.extend_from_slice(&hash);
    v.extend_from_slice(share.identity.as_bytes());
    v
}

fn unpack(bytes: &[u8]) -> Option<Share> {
    if bytes.len() < 48 {
        return None;
    }
    let at = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
    let difficulty = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
    let hash: [u8; 32] = bytes[16..48].try_into().ok()?;
    let identity = String::from_utf8_lossy(&bytes[48..]).into_owned();
    Some(Share { at, identity, difficulty, hash: Some(hash) })
}

fn to_io(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

/// The durable ledger: a redb database of every retained share. It owns durability (a
/// committed share is fsynced), deduplication (the `BY_HASH` table), and retention (a range
/// delete); `Ledger` holds the in-memory window and reads from it.
struct Store {
    db: Database,
    /// The sequence number the next inserted share takes, one past the highest stored.
    next_seq: u64,
    /// The count of most recent shares to retain, or `None` to keep every one.
    retain_bound: Option<u64>,
}

impl Store {
    /// Open the ledger at `path`, creating it if absent. With `chain`, the ledger's chain
    /// stamp must match it: a ledger stamped for another chain is refused with
    /// `InvalidData`, and one with no stamp (written before stamps existed) is stamped now.
    /// Without `chain` (`--dump-ledger`) the stamp is neither checked nor written. Returns
    /// whether this open stamped the ledger.
    fn open(path: &Path, keep: Option<usize>, chain: Option<&str>) -> io::Result<(Self, bool)> {
        // redb takes an exclusive lock on the file, so a second pool on the same ledger is
        // refused here rather than corrupting the share ledger.
        let db = Database::create(path).map_err(to_io)?;
        // Create the tables if the database is new, check or write the chain stamp, and find
        // where the sequence continues.
        let w = db.begin_write().map_err(to_io)?;
        let mut stamped = false;
        {
            // Whether shares were recorded before this open: an unstamped ledger holding
            // some is one written before stamps existed and adopted now, which is reported;
            // an empty one is simply created stamped.
            let held_shares = !w.open_table(SHARES).map_err(to_io)?.is_empty().map_err(to_io)?;
            w.open_table(BY_HASH).map_err(to_io)?;
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
        }
        w.commit().map_err(to_io)?;
        let next_seq = {
            let r = db.begin_read().map_err(to_io)?;
            let shares = r.open_table(SHARES).map_err(to_io)?;
            shares.last().map_err(to_io)?.map(|(k, _)| k.value() + 1).unwrap_or(0)
        };
        let retain = keep.map(|k| (k.max(1) as u64).saturating_mul(SHARES_PER_KEEP_UNIT));
        Ok((Store { db, next_seq, retain_bound: retain }, stamped))
    }

    /// The chain stamp, or `None` for a ledger written before stamps existed.
    #[cfg(test)]
    fn chain(&self) -> io::Result<Option<String>> {
        let r = self.db.begin_read().map_err(to_io)?;
        let meta = r.open_table(META).map_err(to_io)?;
        Ok(meta.get(META_CHAIN).map_err(to_io)?.map(|v| v.value().to_string()))
    }

    /// Store a share durably. Returns `false` if its hash is already present, so it is not
    /// credited twice. The share is newly stored exactly when this returns `Ok(true)`;
    /// `Ok(false)` means it was already stored by an earlier insert.
    fn insert(&mut self, share: &Share) -> io::Result<bool> {
        let hash = share.hash.expect("a recorded share has a hash");
        let mut w = self.db.begin_write().map_err(to_io)?;
        w.set_durability(Durability::Immediate).map_err(to_io)?;
        let inserted = {
            let mut by_hash = w.open_table(BY_HASH).map_err(to_io)?;
            if by_hash.get(hash.as_slice()).map_err(to_io)?.is_some() {
                false
            } else {
                let seq = self.next_seq;
                w.open_table(SHARES)
                    .map_err(to_io)?
                    .insert(seq, pack(share).as_slice())
                    .map_err(to_io)?;
                by_hash.insert(hash.as_slice(), seq).map_err(to_io)?;
                true
            }
        };
        w.commit().map_err(to_io)?;
        if inserted {
            self.next_seq += 1;
        }
        Ok(inserted)
    }

    /// Read the newest shares, returned oldest first, until their summed difficulty reaches
    /// `window`.
    fn read_back(&self, window: u128) -> io::Result<(Vec<Share>, ReadBack)> {
        let r = self.db.begin_read().map_err(to_io)?;
        let shares = r.open_table(SHARES).map_err(to_io)?;
        let mut collected = Vec::new();
        let mut work = 0u128;
        let mut read_back = ReadBack::default();
        let mut iter = shares.iter().map_err(to_io)?;
        // The in-memory window holds at most `MAX_SHARES` (`trim` enforces it), so reading
        // more than that from the store is discarded again by `trim`. Stop at the cap.
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
        // Truncated means the retained ledger ran out before covering the window, which the
        // caller reports as a retention shortfall. Stopping at the count cap is a different
        // condition (warned about by `trim`) and is not a retention shortfall.
        read_back.truncated = work < window && !hit_count_cap;
        collected.reverse();
        Ok((collected, read_back))
    }

    /// Delete the oldest shares beyond the retention bound. Returns how many were removed.
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
        let mut w = self.db.begin_write().map_err(to_io)?;
        w.set_durability(Durability::Immediate).map_err(to_io)?;
        let mut removed = 0usize;
        {
            let mut shares = w.open_table(SHARES).map_err(to_io)?;
            let mut by_hash = w.open_table(BY_HASH).map_err(to_io)?;
            // The oldest `surplus` rows, with the hash to remove from the index.
            let oldest: Vec<(u64, [u8; 32])> = shares
                .iter()
                .map_err(to_io)?
                .take(surplus as usize)
                .filter_map(|entry| {
                    let (seq, value) = entry.ok()?;
                    let hash = value.value().get(16..48)?.try_into().ok()?;
                    Some((seq.value(), hash))
                })
                .collect();
            for (seq, hash) in oldest {
                shares.remove(seq).map_err(to_io)?;
                by_hash.remove(hash.as_slice()).map_err(to_io)?;
                removed += 1;
            }
        }
        w.commit().map_err(to_io)?;
        Ok(removed)
    }

    /// Every stored share, oldest first, for exporting the ledger.
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
    /// Shares the last retention pass removed, for the caller to report.
    removed: usize,
    shares: VecDeque<Share>,
    work_per_identity: HashMap<String, u128>,
    total_work: u128,
    window: u128,
    store: Option<Store>,
    /// Whether the newest `MAX_SHARES` shares hold less work than `window`, so the count cap,
    /// not the work-based trim, is bounding the payout set. Set when the count cap first
    /// drops a share and cleared when it stops, so the warning is emitted once per entry into
    /// that condition rather than per share.
    count_capped: bool,
}

impl Ledger {
    pub fn new(window: u128) -> Self {
        Ledger {
            removed: 0,
            shares: VecDeque::new(),
            work_per_identity: HashMap::new(),
            total_work: 0,
            window: window.max(1),
            store: None,
            count_capped: false,
        }
    }

    /// Open the ledger at `path` for the shares of `chain` (the name the node reports:
    /// `main`, `testnet4`, ...), which the ledger is stamped with; see `Store::open`. `None`
    /// opens without the chain check, for reading a ledger back.
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
        for share in shares {
            ledger.push(share);
            ledger.trim();
        }
        ledger.store = Some(store);
        Ok((ledger, read_back))
    }

    /// Set the window, and when it grows and a ledger backs it, re-read the store so the
    /// shares a narrower window had dropped re-enter it. This is the TIDES property that work
    /// is rewarded again when difficulty rises: a share never leaves the ledger, only the
    /// active window, and a later difficulty increase widens the window back over it.
    ///
    /// Returns how many shares were re-read from the store: zero when narrowing, and zero for
    /// a ledger with no store, whose trimmed shares are gone from memory. The re-read span is
    /// bounded by what `--ledger-keep` has retained.
    pub fn set_window(&mut self, window: u128) -> usize {
        let window = window.max(1);
        let widened = window > self.window;
        self.window = window;
        let re_read = if widened { self.refill() } else { 0 };
        self.trim();
        re_read
    }

    /// Rebuild the in-memory window from the store, so shares trimmed from a narrower window
    /// are in a wider one. Every in-memory share was committed durably by `record`
    /// before it was held, so the store is a superset of memory and re-reading it cannot lose
    /// a share. Returns how many more shares the window holds than before.
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
        self.shares.clear();
        self.work_per_identity.clear();
        self.total_work = 0;
        for share in shares {
            self.push(share);
            self.trim();
        }
        self.shares.len().saturating_sub(before)
    }

    /// Every share the store holds, oldest first, for exporting the ledger. Empty for a
    /// file-less ledger.
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

    /// How many shares the last retention pass removed, and zero once read.
    pub fn take_removed(&mut self) -> usize {
        std::mem::replace(&mut self.removed, 0)
    }

    /// The hashes of the shares the window still holds, oldest first.
    ///
    /// The pool's `ReplayGuard` is in memory only, so a restart loses every hash it held;
    /// these are those hashes, and they are already on disk. The window is the right
    /// scope for that: a share old enough to have been trimmed out of it is one that as
    /// much work again has been recorded since, which puts it far outside both the ntime
    /// window and the tip its job was mined on, so the staleness test refuses it anyway.
    pub fn hashes(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.shares.iter().filter_map(|s| s.hash.as_ref())
    }

    pub fn record(
        &mut self,
        at: u64,
        identity: &str,
        difficulty: u64,
        hash: &[u8; 32],
    ) -> io::Result<()> {
        let share = Share { at, identity: identity.to_string(), difficulty, hash: Some(*hash) };
        if let Some(store) = &mut self.store {
            // The insert is durable when it returns Ok, before any in-memory state is modified,
            // so an Err allows the caller to remove the hash from the `ReplayGuard` and
            // accept a resend. A hash already stored is credited once (Ok(false)); it is the
            // durable complement to the in-memory `ReplayGuard`, and the share is not added to
            // the window a second time.
            if !store.insert(&share)? {
                return Ok(());
            }
        }
        self.push(share);
        self.trim();
        // Past this point the share is durable and credited. Retention is separate; a
        // failure must not be reported as a record failure, or the caller would remove from
        // the `ReplayGuard` a hash that is already stored and already counted, and a resend
        // would be credited and stored a second time. Report the failure separately.
        if let Some(store) = &mut self.store {
            match store.retain() {
                Ok(removed) => self.removed = removed,
                Err(e) => log::warn!("ledger retention failed; the share is recorded ({e})"),
            }
        }
        Ok(())
    }

    /// The summed share difficulty of each identity in the window, largest first.
    pub fn work_by_identity(&self) -> Vec<(String, u128)> {
        let mut v: Vec<(String, u128)> =
            self.work_per_identity.iter().map(|(k, d)| (k.clone(), *d)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v
    }

    /// Divides `value` among the identities in the window, largest first. The amounts total
    /// `value` exactly, so the gateway has no remainder to pay to the pool's script (it
    /// writes a zero-value OP_RETURN output in its place).
    ///
    /// An identity past `max_outputs` or under `min_payout` leaves the denominator as well
    /// as the output list, so its work does not reduce what the paid miners receive.
    pub fn split(&self, value: u64, min_payout: u64, max_outputs: usize) -> Vec<(String, u64)> {
        if self.total_work == 0 || value == 0 || max_outputs == 0 {
            return Vec::new();
        }
        let mut kept = self.work_by_identity();
        kept.truncate(max_outputs);
        let mut work: u128 = kept.iter().map(|(_, w)| *w).sum();

        // Sorted descending, so only the last one can be under the minimum.
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
            // The last divisor is its own work, so it takes the remainder.
            let amount = (u128::from(left).saturating_mul(w) / work) as u64;
            left -= amount;
            work -= w;
            // Omitting a zero cannot change the total.
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
        self.shares.push_back(share);
    }

    /// Drops the oldest shares while the ones left still cover the window, so the window
    /// is never trimmed to less than the work it is meant to represent.
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
            }
        }
    }
}

/// The identity a share is credited to: the username up to the first `.`, expected to be an
/// address. The gateway sends its configured address bare, `address.workername`, or with
/// `datum_pool_pass_full_users` the miner's username verbatim (`datum_protocol.c`), so
/// everything from the first dot is the worker name and not part of who gets paid.
pub fn identity_of(username: &str) -> &str {
    username.split('.').next().unwrap_or(username)
}

pub fn window_for_difficulty(network_difficulty: f64, multiple: f64, floor: u128) -> u128 {
    let w = network_difficulty * multiple;
    let scaled = if w.is_finite() && w >= 1.0 { w as u128 } else { 1 };
    scaled.max(floor.max(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(n: u64) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&n.to_be_bytes());
        h
    }

    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(what: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("ratum-ledger-{what}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }

        fn join(&self, name: &str) -> std::path::PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn ledger_with(window: u128, shares: &[(&str, u64)]) -> Ledger {
        let mut l = Ledger::new(window);
        for (i, (identity, difficulty)) in shares.iter().enumerate() {
            l.record(1_000 + i as u64, identity, *difficulty, &hash(i as u64)).unwrap();
        }
        l
    }

    #[test]
    fn credits_shares_by_identity() {
        let l = ledger_with(1_000_000, &[("alice", 16), ("bob", 32), ("alice", 16)]);
        assert_eq!(l.total_work(), 64);
        assert_eq!(l.len(), 3);
        assert_eq!(l.work_by_identity(), vec![("alice".into(), 32), ("bob".into(), 32)]);
    }

    #[test]
    fn splits_value_in_proportion_to_work() {
        let l = ledger_with(1_000_000, &[("alice", 75), ("bob", 25)]);
        let split = l.split(1_000_000, 0, 512);
        assert_eq!(split, vec![("alice".into(), 750_000), ("bob".into(), 250_000)]);
        assert_eq!(split.iter().map(|(_, v)| v).sum::<u64>(), 1_000_000);
    }

    #[test]
    fn no_remainder_is_left_for_the_pool() {
        // Three equal miners cannot divide 100 evenly. The odd satoshi still goes to a
        // miner rather than to the pool's script.
        let l = ledger_with(1_000_000, &[("a", 1), ("b", 1), ("c", 1)]);
        let split = l.split(100, 0, 512);
        assert_eq!(split.len(), 3);
        assert_eq!(split.iter().map(|(_, v)| v).sum::<u64>(), 100);
    }

    #[test]
    fn the_amounts_always_total_the_value() {
        // Work counts and values chosen to be mutually indivisible, so every case has a
        // remainder to place.
        for value in [1u64, 7, 99, 1_000_003, 3_125_000_000] {
            for works in [
                &[("a", 1u64)][..],
                &[("a", 1), ("b", 2)][..],
                &[("a", 7), ("b", 11), ("c", 13)][..],
                &[("a", 1), ("b", 1), ("c", 1), ("d", 1), ("e", 1), ("f", 1), ("g", 1)][..],
            ] {
                let l = ledger_with(u128::MAX, works);
                let split = l.split(value, 0, 512);
                let paid: u64 = split.iter().map(|(_, v)| v).sum();
                assert_eq!(paid, value, "value {value} over {} miners", works.len());
            }
        }
    }

    #[test]
    fn amounts_below_the_minimum_are_not_paid() {
        let l = ledger_with(1_000_000, &[("large", 999), ("small", 1)]);
        assert_eq!(l.split(1_000_000, 0, 512).len(), 2);

        // The small miner's 1000 sats are under the minimum, so it gets no output. Its work
        // leaves the denominator with it, so the large one is paid the whole value rather than
        // the 999_000 its share of the untrimmed window would have been; the difference
        // stays with a miner instead of reaching the pool.
        let split = l.split(1_000_000, 10_000, 512);
        assert_eq!(split, vec![("large".into(), 1_000_000)]);
    }

    #[test]
    fn dropping_the_smallest_can_raise_the_rest_over_the_minimum() {
        // Each of the four holds a quarter of 40_000, so 10_000 each, exactly at the
        // minimum. Raising it by one satoshi puts all four under, and the set has to
        // shrink until what is left clears it: three would take 13_333 each.
        let l = ledger_with(1_000_000, &[("a", 1), ("b", 1), ("c", 1), ("d", 1)]);
        assert_eq!(l.split(40_000, 10_000, 512).len(), 4);
        let split = l.split(40_000, 10_001, 512);
        assert_eq!(split.len(), 3);
        assert_eq!(split.iter().map(|(_, v)| v).sum::<u64>(), 40_000);
        assert!(split.iter().all(|(_, v)| *v >= 10_001));
    }

    #[test]
    fn a_value_under_the_minimum_pays_nobody() {
        let l = ledger_with(1_000_000, &[("a", 1), ("b", 1)]);
        assert!(l.split(9_999, 10_000, 512).is_empty());
    }

    #[test]
    fn output_count_is_capped_largest_first() {
        let l = ledger_with(1_000_000, &[("a", 4), ("b", 3), ("c", 2), ("d", 1)]);
        let split = l.split(1_000_000, 0, 2);
        assert_eq!(split.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(), vec!["a", "b"]);
    }

    #[test]
    fn an_empty_window_pays_nobody() {
        let l = Ledger::new(1_000);
        assert!(l.split(5_000_000_000, 0, 512).is_empty());
        assert_eq!(l.total_work(), 0);
        assert!(l.is_empty());
    }

    #[test]
    fn zero_value_or_no_outputs_pays_nobody() {
        let l = ledger_with(1_000, &[("a", 8)]);
        assert!(l.split(0, 0, 512).is_empty());
        assert!(l.split(1_000_000, 0, 0).is_empty());
    }

    #[test]
    fn the_window_slides_by_work() {
        let mut l = Ledger::new(100);
        for i in 0..10 {
            l.record(i, "a", 32, &hash(i)).unwrap();
        }
        assert!(l.total_work() >= 100, "window holds {} < 100", l.total_work());
        assert!(l.total_work() < 100 + 32, "window holds {}, more than needed", l.total_work());
        assert_eq!(l.work_by_identity(), vec![("a".into(), l.total_work())]);
    }

    #[test]
    fn a_miner_with_no_recent_shares_is_trimmed_from_the_window() {
        let mut l = Ledger::new(64);
        for i in 0..4 {
            l.record(0, "leaver", 16, &hash(i)).unwrap();
        }
        assert_eq!(l.split(1_000, 0, 512), vec![("leaver".into(), 1_000)]);
        for i in 0..4 {
            l.record(1, "joiner", 16, &hash(100 + i)).unwrap();
        }
        let split = l.split(1_000, 0, 512);
        assert_eq!(split, vec![("joiner".into(), 1_000)]);
        assert!(!l.work_by_identity().iter().any(|(k, _)| k == "leaver"));
    }

    #[test]
    fn a_window_smaller_than_one_share_still_pays_it() {
        let mut l = Ledger::new(1);
        l.record(0, "a", 16384, &hash(0)).unwrap();
        l.record(1, "b", 16384, &hash(1)).unwrap();
        assert_eq!(l.len(), 1);
        assert_eq!(l.split(1_000, 0, 512), vec![("b".into(), 1_000)]);
    }

    #[test]
    fn large_values_do_not_overflow() {
        let mut l = Ledger::new(u128::MAX);
        l.record(0, "a", u64::MAX / 2, &hash(0)).unwrap();
        l.record(1, "b", u64::MAX / 2, &hash(1)).unwrap();
        let split = l.split(2_100_000_000_000_000, 0, 512);
        assert_eq!(split.len(), 2);
        assert_eq!(split[0].1, 2_100_000_000_000_000 / 2);
    }

    #[test]
    fn identity_is_the_address_before_the_worker_name() {
        assert_eq!(identity_of("bc1qexample.rig1"), "bc1qexample");
        assert_eq!(identity_of("bc1qexample"), "bc1qexample");
        assert_eq!(identity_of("bc1qexample.rig1.gpu2"), "bc1qexample");
        assert_eq!(identity_of(""), "");
    }

    #[test]
    fn a_window_of_u128_max_still_caps_the_share_count() {
        let mut l = Ledger::new(u128::MAX);
        for i in 0..(MAX_SHARES + 50) {
            l.record(i as u64, "a", 1, &hash(i as u64)).unwrap();
        }
        assert_eq!(l.len(), MAX_SHARES);
        assert_eq!(l.total_work(), MAX_SHARES as u128);
        assert_eq!(l.work_by_identity(), vec![("a".into(), MAX_SHARES as u128)]);
    }

    #[test]
    fn window_tracks_network_difficulty_with_a_floor() {
        assert_eq!(window_for_difficulty(1_000.0, 8.0, 1), 8_000);
        assert_eq!(window_for_difficulty(4.6e-10, 8.0, 1), 1);
        assert_eq!(window_for_difficulty(4.6e-10, 8.0, 5_000), 5_000);
        assert_eq!(window_for_difficulty(f64::NAN, 8.0, 1), 1);
        assert_eq!(window_for_difficulty(0.0, 8.0, 1), 1);
        assert_eq!(window_for_difficulty(1_000.0, 8.0, 100), 8_000);
        assert_eq!(window_for_difficulty(1_000.0, 8.0, 100_000), 100_000);
    }

    // A ledger backed by a redb store, for the durability tests below.
    fn open(scratch: &Scratch, window: u128, keep: Option<usize>) -> (Ledger, ReadBack) {
        Ledger::open(&scratch.join("regtest.redb"), window, keep, Some("regtest")).unwrap()
    }

    #[test]
    fn a_new_ledger_is_stamped_with_its_chain() {
        let scratch = Scratch::new("stamp-new");
        let path = scratch.join("main.redb");
        let (_, read_back) = Ledger::open(&path, 1, None, Some("main")).unwrap();
        assert!(!read_back.stamped, "creating a ledger is not adopting one");
        let (store, _) = Store::open(&path, None, None).unwrap();
        assert_eq!(store.chain().unwrap().as_deref(), Some("main"));
    }

    #[test]
    fn a_ledger_of_another_chain_is_refused() {
        let scratch = Scratch::new("stamp-other");
        let path = scratch.join("shares.redb");
        drop(Ledger::open(&path, 1, None, Some("testnet4")).unwrap());
        let err = Ledger::open(&path, 1, None, Some("main"))
            .err()
            .expect("a ledger of another chain is refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let msg = err.to_string();
        assert!(msg.contains("chain testnet4") && msg.contains("chain main"), "{msg}");
        // Reading it back does not check the stamp.
        drop(Ledger::open(&path, 1, None, None).unwrap());
        // The refused open wrote nothing: the stamp is unchanged.
        let (store, _) = Store::open(&path, None, None).unwrap();
        assert_eq!(store.chain().unwrap().as_deref(), Some("testnet4"));
    }

    #[test]
    fn an_unstamped_ledger_is_adopted_by_the_first_chain_to_open_it() {
        let scratch = Scratch::new("stamp-adopt");
        let path = scratch.join("shares.redb");
        // Written before stamps existed: opened without a chain, so no stamp.
        {
            let (mut l, _) = Ledger::open(&path, u128::MAX, None, None).unwrap();
            l.record(1, "alice", 16, &hash(1)).unwrap();
        }
        let (store, _) = Store::open(&path, None, None).unwrap();
        assert_eq!(store.chain().unwrap(), None);
        drop(store);
        let (l, read_back) = Ledger::open(&path, u128::MAX, None, Some("testnet4")).unwrap();
        assert!(read_back.stamped);
        assert_eq!(l.len(), 1, "adoption keeps the shares");
        drop(l);
        // Once adopted it belongs to that chain.
        assert!(Ledger::open(&path, 1, None, Some("main")).is_err());
        assert!(!Ledger::open(&path, 1, None, Some("testnet4")).unwrap().1.stamped);
    }

    #[test]
    fn packs_and_unpacks_a_share() {
        let share = Share {
            at: 1_750_000_000,
            identity: "bc1qexample".into(),
            difficulty: 16384,
            hash: Some(hash(7)),
        };
        assert_eq!(unpack(&pack(&share)), Some(share));
        // A row too short to hold the fixed fields is skipped, not misread.
        assert_eq!(unpack(&[0u8; 16]), None);
    }

    #[test]
    fn persists_across_a_restart() {
        let scratch = Scratch::new("restart");
        {
            let (mut l, read_back) = open(&scratch, 1_000_000, None);
            assert_eq!(read_back.skipped, 0);
            l.record(1, "alice", 32, &hash(1)).unwrap();
            l.record(2, "bob", 16, &hash(2)).unwrap();
        }
        {
            let (reopened, read_back) = open(&scratch, 1_000_000, None);
            assert_eq!(read_back.skipped, 0);
            assert_eq!(reopened.total_work(), 48);
            assert_eq!(reopened.work_by_identity(), vec![("alice".into(), 32), ("bob".into(), 16)]);
        }

        {
            let (mut l, _) = open(&scratch, 1_000_000, None);
            l.record(3, "alice", 8, &hash(3)).unwrap();
        }
        let (again, _) = open(&scratch, 1_000_000, None);
        assert_eq!(again.total_work(), 56);
        assert_eq!(again.len(), 3);
    }

    /// The store keys shares by hash, so a resent share is stored and credited once even if it
    /// reaches `record` again: the durable complement to the pool's in-memory `ReplayGuard`.
    #[test]
    fn a_resent_hash_is_credited_once() {
        let scratch = Scratch::new("resend");
        {
            let (mut l, _) = open(&scratch, 1_000_000, None);
            l.record(1, "alice", 16, &hash(1)).unwrap();
            l.record(2, "bob", 32, &hash(2)).unwrap();
            l.record(1, "alice", 16, &hash(1)).unwrap(); // the same hash again
            assert_eq!(l.total_work(), 48, "alice's share counts once, not twice");
            assert_eq!(l.len(), 2);
        }
        let (reopened, _) = open(&scratch, 1_000_000, None);
        assert_eq!(reopened.total_work(), 48, "and still once across a restart");
    }

    /// The hashes the pool's `ReplayGuard` loses when it restarts, which the ledger holds
    /// for it, persist in the store.
    #[test]
    fn hashes_persist_across_a_restart() {
        let scratch = Scratch::new("hashes");
        {
            let (mut l, _) = open(&scratch, 1_000_000, None);
            l.record(1, "alice", 16, &hash(1)).unwrap();
            l.record(2, "bob", 32, &hash(2)).unwrap();
        }
        let (l, _) = open(&scratch, 1_000_000, None);
        assert_eq!(l.hashes().copied().collect::<Vec<_>>(), vec![hash(1), hash(2)], "oldest first");
    }

    #[test]
    fn hashes_returns_the_hashes_the_window_holds() {
        let mut l = ledger_with(1_000_000, &[("alice", 16), ("bob", 32)]);
        l.record(1_100, "carol", 8, &hash(99)).unwrap();
        assert_eq!(l.hashes().copied().collect::<Vec<_>>(), vec![hash(0), hash(1), hash(99)]);

        // Only what the window still holds: trimming drops a share's hash with it.
        let mut narrow = Ledger::new(8);
        narrow.record(1, "alice", 8, &hash(1)).unwrap();
        narrow.record(2, "bob", 8, &hash(2)).unwrap();
        assert_eq!(narrow.hashes().copied().collect::<Vec<_>>(), vec![hash(2)]);
    }

    #[test]
    fn read_back_reads_only_as_far_back_as_the_window_needs() {
        let scratch = Scratch::new("read-back-depth");
        {
            let (mut l, _) = open(&scratch, u128::MAX, None);
            for i in 0..1_000u64 {
                l.record(i, "miner00", 16, &hash(i)).unwrap();
            }
        }
        // A ten-share window recovers about ten shares of work, not all thousand.
        let (l, read_back) = open(&scratch, 160, None);
        assert!(!read_back.truncated);
        assert!(l.total_work() >= 160, "covers the window");
        assert!(l.len() < 100, "without reading the whole store: {} shares", l.len());
        assert_eq!(l.shares.back().unwrap().at, 999, "and the newest work is in it");
    }

    #[test]
    fn read_back_reports_truncated_when_the_store_holds_less_work_than_the_window() {
        let scratch = Scratch::new("read-back-short");
        {
            let (mut l, _) = open(&scratch, u128::MAX, None);
            for i in 0..5u64 {
                l.record(i, "miner00", 16, &hash(i)).unwrap();
            }
        }
        let (l, read_back) = open(&scratch, 1_000_000, None);
        assert!(read_back.truncated, "the store holds less work than the window requires");
        assert_eq!(l.len(), 5);
    }

    /// Without a store the window can only narrow: narrowing drops the work that no
    /// longer fits, and there is nowhere to read it back from, so widening does not undo it.
    #[test]
    fn narrowing_a_file_less_windows_trim_is_not_undone_by_widening() {
        let mut l = ledger_with(1_000_000, &[("alice", 16), ("bob", 32), ("carol", 8)]);
        assert_eq!(l.total_work(), 56);
        assert_eq!(l.set_window(8), 0);
        assert_eq!(l.work_by_identity(), vec![("carol".into(), 8)]);
        assert_eq!(l.set_window(1_000_000), 0, "no store to read the trimmed shares back from");
        assert_eq!(l.total_work(), 8, "what was trimmed is gone rather than hidden");
        assert_eq!(l.len(), 1);
    }

    /// The TIDES property: with retention unbounded a share never leaves the store, only the
    /// active window, so a difficulty rise that widens the window re-reads the shares a narrower
    /// one had dropped.
    #[test]
    fn widening_the_window_re_reads_shares_from_the_store() {
        let scratch = Scratch::new("widen");
        let (mut l, _) = open(&scratch, 56, None);
        l.record(1, "alice", 16, &hash(1)).unwrap();
        l.record(2, "bob", 32, &hash(2)).unwrap();
        l.record(3, "carol", 8, &hash(3)).unwrap();

        // A difficulty drop narrows the window; the older shares are trimmed but stay stored.
        assert_eq!(l.set_window(8), 0);
        assert_eq!(l.work_by_identity(), vec![("carol".into(), 8)]);
        assert_eq!(l.hashes().copied().collect::<Vec<_>>(), vec![hash(3)]);

        // A difficulty rise widens it again, and the two trimmed are back and credited.
        assert_eq!(l.set_window(56), 2, "alice and bob are re-read");
        assert_eq!(l.total_work(), 56);
        assert_eq!(
            l.work_by_identity(),
            vec![("bob".into(), 32), ("alice".into(), 16), ("carol".into(), 8)]
        );
        assert_eq!(l.hashes().copied().collect::<Vec<_>>(), vec![hash(1), hash(2), hash(3)]);
    }

    /// Retention deletes the oldest shares beyond the bound, keeping the most recent. Tested
    /// on the store directly with a small bound, since a `--ledger-keep` unit is 2^20 shares.
    #[test]
    fn retention_keeps_the_most_recent_shares() {
        let scratch = Scratch::new("retain");
        let (mut store, _) = Store::open(&scratch.join("regtest.redb"), None, None).unwrap();
        store.retain_bound = Some(5);
        for i in 0..12u64 {
            let share = Share { at: i, identity: "m".into(), difficulty: 16, hash: Some(hash(i)) };
            store.insert(&share).unwrap();
            store.retain().unwrap();
        }
        let dumped = store.dump().unwrap();
        assert_eq!(dumped.len(), 5, "only the five most recent are retained");
        assert_eq!(dumped.first().unwrap().at, 7, "the oldest kept");
        assert_eq!(dumped.last().unwrap().at, 11, "through the newest");
        // A removed share's hash is gone from the dedup index, so the same hash inserts again.
        assert!(
            store
                .insert(&Share { at: 0, identity: "m".into(), difficulty: 16, hash: Some(hash(0)) })
                .unwrap()
        );
    }

    #[test]
    fn dump_returns_every_stored_share_oldest_first() {
        let scratch = Scratch::new("dump");
        let (mut l, _) = open(&scratch, 8, None); // a window smaller than what is recorded
        l.record(1, "alice", 16, &hash(1)).unwrap();
        l.record(2, "bob", 16, &hash(2)).unwrap();
        l.record(3, "carol", 16, &hash(3)).unwrap();
        assert_eq!(l.len(), 1, "the window holds only the newest");
        let dumped = l.dump().unwrap();
        assert_eq!(dumped.len(), 3, "but the store holds all three");
        assert_eq!(dumped.iter().map(|s| s.at).collect::<Vec<_>>(), vec![1, 2, 3]);
    }
}
