mod store;

use std::collections::{HashMap, VecDeque};
use std::io;
use std::path::Path;
use store::Store;

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

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn hash(n: u64) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&n.to_be_bytes());
        h
    }

    pub(super) struct Scratch(std::path::PathBuf);

    impl Scratch {
        pub(super) fn new(what: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("ratum-ledger-{what}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }

        pub(super) fn join(&self, name: &str) -> std::path::PathBuf {
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
            l.record(1_000 + i as u64, identity, *difficulty, &hash(i as u64), "").unwrap();
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
        let l = ledger_with(1_000_000, &[("a", 1), ("b", 1), ("c", 1)]);
        let split = l.split(100, 0, 512);
        assert_eq!(split.len(), 3);
        assert_eq!(split.iter().map(|(_, v)| v).sum::<u64>(), 100);
    }

    #[test]
    fn the_amounts_always_total_the_value() {
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

        let split = l.split(1_000_000, 10_000, 512);
        assert_eq!(split, vec![("large".into(), 1_000_000)]);
    }

    #[test]
    fn dropping_the_smallest_can_raise_the_rest_over_the_minimum() {
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
            l.record(i, "a", 32, &hash(i), "").unwrap();
        }
        assert!(l.total_work() >= 100, "window holds {} < 100", l.total_work());
        assert!(l.total_work() < 100 + 32, "window holds {}, more than needed", l.total_work());
        assert_eq!(l.work_by_identity(), vec![("a".into(), l.total_work())]);
    }

    #[test]
    fn a_miner_with_no_recent_shares_is_trimmed_from_the_window() {
        let mut l = Ledger::new(64);
        for i in 0..4 {
            l.record(0, "leaver", 16, &hash(i), "").unwrap();
        }
        assert_eq!(l.split(1_000, 0, 512), vec![("leaver".into(), 1_000)]);
        for i in 0..4 {
            l.record(1, "joiner", 16, &hash(100 + i), "").unwrap();
        }
        let split = l.split(1_000, 0, 512);
        assert_eq!(split, vec![("joiner".into(), 1_000)]);
        assert!(!l.work_by_identity().iter().any(|(k, _)| k == "leaver"));
    }

    #[test]
    fn a_window_smaller_than_one_share_still_pays_it() {
        let mut l = Ledger::new(1);
        l.record(0, "a", 16384, &hash(0), "").unwrap();
        l.record(1, "b", 16384, &hash(1), "").unwrap();
        assert_eq!(l.len(), 1);
        assert_eq!(l.split(1_000, 0, 512), vec![("b".into(), 1_000)]);
    }

    #[test]
    fn large_values_do_not_overflow() {
        let mut l = Ledger::new(u128::MAX);
        l.record(0, "a", u64::MAX / 2, &hash(0), "").unwrap();
        l.record(1, "b", u64::MAX / 2, &hash(1), "").unwrap();
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
            l.record(i as u64, "a", 1, &hash(i as u64), "").unwrap();
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

    fn open(scratch: &Scratch, window: u128, keep: Option<usize>) -> (Ledger, ReadBack) {
        Ledger::open(&scratch.join("regtest.redb"), window, keep, Some("regtest")).unwrap()
    }

    #[test]
    fn a_new_ledger_is_stamped_with_its_chain() {
        let scratch = Scratch::new("stamp-new");
        let path = scratch.join("main.redb");
        let (l, read_back) = Ledger::open(&path, 1, None, Some("main")).unwrap();
        assert!(!read_back.stamped, "creating a ledger is not adopting one");
        drop(l);
        let (l, again) = Ledger::open(&path, 1, None, Some("main")).unwrap();
        assert!(!again.stamped, "the stamp is already main");
        drop(l);
        assert!(
            Ledger::open(&path, 1, None, Some("testnet4")).is_err(),
            "the file is stamped main"
        );
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
        drop(Ledger::open(&path, 1, None, None).unwrap());
        assert!(
            Ledger::open(&path, 1, None, Some("main")).is_err(),
            "opening without a chain does not clear the stamp"
        );
    }

    #[test]
    fn an_unstamped_ledger_is_adopted_by_the_first_chain_to_open_it() {
        let scratch = Scratch::new("stamp-adopt");
        let path = scratch.join("shares.redb");
        {
            let (mut l, _) = Ledger::open(&path, u128::MAX, None, None).unwrap();
            l.record(1, "alice", 16, &hash(1), "").unwrap();
        }
        let (l, read_back) = Ledger::open(&path, u128::MAX, None, Some("testnet4")).unwrap();
        assert!(read_back.stamped);
        assert_eq!(l.len(), 1, "adoption keeps the shares");
        drop(l);
        assert!(Ledger::open(&path, 1, None, Some("main")).is_err());
        assert!(!Ledger::open(&path, 1, None, Some("testnet4")).unwrap().1.stamped);
    }

    #[test]
    fn the_tag_is_the_newest_share_of_each_identity_and_leaves_with_it() {
        let mut l = Ledger::new(32);
        l.record(1, "alice", 16, &hash(1), "old").unwrap();
        l.record(2, "alice", 16, &hash(2), "new").unwrap();
        l.record(3, "bob", 16, &hash(3), "").unwrap();
        let tags = l.tags_by_identity();
        assert_eq!(tags.get("alice").map(String::as_str), Some("new"));
        assert_eq!(tags.get("bob").map(String::as_str), Some(""));
        l.record(4, "carol", 16, &hash(4), "").unwrap();
        l.record(5, "carol", 16, &hash(5), "").unwrap();
        assert!(!l.tags_by_identity().contains_key("alice"));
    }

    #[test]
    fn persists_across_a_restart() {
        let scratch = Scratch::new("restart");
        {
            let (mut l, read_back) = open(&scratch, 1_000_000, None);
            assert_eq!(read_back.skipped, 0);
            l.record(1, "alice", 32, &hash(1), "").unwrap();
            l.record(2, "bob", 16, &hash(2), "").unwrap();
        }
        {
            let (reopened, read_back) = open(&scratch, 1_000_000, None);
            assert_eq!(read_back.skipped, 0);
            assert_eq!(reopened.total_work(), 48);
            assert_eq!(reopened.work_by_identity(), vec![("alice".into(), 32), ("bob".into(), 16)]);
        }

        {
            let (mut l, _) = open(&scratch, 1_000_000, None);
            l.record(3, "alice", 8, &hash(3), "").unwrap();
        }
        let (again, _) = open(&scratch, 1_000_000, None);
        assert_eq!(again.total_work(), 56);
        assert_eq!(again.len(), 3);
    }

    #[test]
    fn a_resent_hash_is_credited_once() {
        let scratch = Scratch::new("resend");
        {
            let (mut l, _) = open(&scratch, 1_000_000, None);
            l.record(1, "alice", 16, &hash(1), "").unwrap();
            l.record(2, "bob", 32, &hash(2), "").unwrap();
            l.record(1, "alice", 16, &hash(1), "").unwrap();
            assert_eq!(l.total_work(), 48, "alice's share counts once, not twice");
            assert_eq!(l.len(), 2);
        }
        let (reopened, _) = open(&scratch, 1_000_000, None);
        assert_eq!(reopened.total_work(), 48, "and still once across a restart");
    }

    #[test]
    fn hashes_persist_across_a_restart() {
        let scratch = Scratch::new("hashes");
        {
            let (mut l, _) = open(&scratch, 1_000_000, None);
            l.record(1, "alice", 16, &hash(1), "").unwrap();
            l.record(2, "bob", 32, &hash(2), "").unwrap();
        }
        let (l, _) = open(&scratch, 1_000_000, None);
        assert_eq!(l.hashes().copied().collect::<Vec<_>>(), vec![hash(1), hash(2)], "oldest first");
    }

    #[test]
    fn hashes_returns_the_hashes_the_window_holds() {
        let mut l = ledger_with(1_000_000, &[("alice", 16), ("bob", 32)]);
        l.record(1_100, "carol", 8, &hash(99), "").unwrap();
        assert_eq!(l.hashes().copied().collect::<Vec<_>>(), vec![hash(0), hash(1), hash(99)]);

        let mut narrow = Ledger::new(8);
        narrow.record(1, "alice", 8, &hash(1), "").unwrap();
        narrow.record(2, "bob", 8, &hash(2), "").unwrap();
        assert_eq!(narrow.hashes().copied().collect::<Vec<_>>(), vec![hash(2)]);
    }

    #[test]
    fn read_back_reads_only_as_far_back_as_the_window_needs() {
        let scratch = Scratch::new("read-back-depth");
        {
            let (mut l, _) = open(&scratch, u128::MAX, None);
            for i in 0..1_000u64 {
                l.record(i, "miner00", 16, &hash(i), "").unwrap();
            }
        }
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
                l.record(i, "miner00", 16, &hash(i), "").unwrap();
            }
        }
        let (l, read_back) = open(&scratch, 1_000_000, None);
        assert!(read_back.truncated, "the store holds less work than the window requires");
        assert_eq!(l.len(), 5);
    }

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

    #[test]
    fn widening_the_window_re_reads_shares_from_the_store() {
        let scratch = Scratch::new("widen");
        let (mut l, _) = open(&scratch, 56, None);
        l.record(1, "alice", 16, &hash(1), "").unwrap();
        l.record(2, "bob", 32, &hash(2), "").unwrap();
        l.record(3, "carol", 8, &hash(3), "").unwrap();

        assert_eq!(l.set_window(8), 0);
        assert_eq!(l.work_by_identity(), vec![("carol".into(), 8)]);
        assert_eq!(l.hashes().copied().collect::<Vec<_>>(), vec![hash(3)]);

        assert_eq!(l.set_window(56), 2, "alice and bob are re-read");
        assert_eq!(l.total_work(), 56);
        assert_eq!(
            l.work_by_identity(),
            vec![("bob".into(), 32), ("alice".into(), 16), ("carol".into(), 8)]
        );
        assert_eq!(l.hashes().copied().collect::<Vec<_>>(), vec![hash(1), hash(2), hash(3)]);
    }

    #[test]
    fn dump_returns_every_stored_share_oldest_first() {
        let scratch = Scratch::new("dump");
        let (mut l, _) = open(&scratch, 8, None);
        l.record(1, "alice", 16, &hash(1), "").unwrap();
        l.record(2, "bob", 16, &hash(2), "").unwrap();
        l.record(3, "carol", 16, &hash(3), "").unwrap();
        assert_eq!(l.len(), 1, "the window holds only the newest");
        let dumped = l.dump().unwrap();
        assert_eq!(dumped.len(), 3, "but the store holds all three");
        assert_eq!(dumped.iter().map(|s| s.at).collect::<Vec<_>>(), vec![1, 2, 3]);
    }

    pub(super) fn owed(n: u64, settled: Option<u64>) -> OwedBlock {
        OwedBlock {
            at: 100 + n,
            height: 961_640 + n as u32,
            block_hash: hash(0xb10c_0000 + n),
            total: 300 + n,
            settled_at: settled,
            entries: vec![("alice".into(), 200 + n), ("bob".into(), 100)],
        }
    }

    #[test]
    fn owed_blocks_survive_a_reopen_and_settle_once() {
        let scratch = Scratch::new("owed");
        {
            let (mut l, _) = open(&scratch, u128::MAX, None);
            l.record_owed(owed(1, None)).unwrap();
            l.record_owed(owed(2, None)).unwrap();
            l.record_owed(OwedBlock { total: 9_999, ..owed(1, None) }).unwrap();
            assert_eq!(l.owed().len(), 2);
            assert_eq!(l.owed()[0].total, 300 + 1, "the first record stands");
        }
        let (mut l, _) = open(&scratch, u128::MAX, None);
        assert_eq!(l.owed().len(), 2, "read back from the store");
        assert_eq!(l.owed()[0].entries, vec![("alice".into(), 201), ("bob".into(), 100)]);

        let settled = l.settle_owed(&owed(1, None).block_hash, 5_000).unwrap().unwrap();
        assert_eq!(settled.settled_at, Some(5_000));
        assert_eq!(l.owed()[0].settled_at, Some(5_000), "the in-memory copy follows");
        let again = l.settle_owed(&owed(1, None).block_hash, 6_000).unwrap().unwrap();
        assert_eq!(again.settled_at, Some(5_000));
        assert!(l.settle_owed(&hash(0xdead), 6_000).unwrap().is_none());
        drop(l);

        let (l, _) = open(&scratch, u128::MAX, None);
        assert_eq!(l.owed()[0].settled_at, Some(5_000), "settlement is durable");
        assert_eq!(l.owed()[1].settled_at, None);
    }

    #[test]
    fn a_voided_owed_block_is_removed_durably() {
        let scratch = Scratch::new("void");
        {
            let (mut l, _) = open(&scratch, u128::MAX, None);
            l.record_owed(owed(1, None)).unwrap();
            l.record_owed(owed(2, None)).unwrap();
            let voided = l.void_owed(&owed(1, None).block_hash).unwrap().unwrap();
            assert_eq!(voided.total, 300 + 1);
            assert_eq!(l.owed().len(), 1);
            assert!(l.void_owed(&owed(1, None).block_hash).unwrap().is_none());
        }
        let (l, _) = open(&scratch, u128::MAX, None);
        assert_eq!(l.owed().len(), 1, "the removal is durable");
        assert_eq!(l.owed()[0].block_hash, owed(2, None).block_hash);

        let mut fileless = Ledger::new(u128::MAX);
        fileless.record_owed(owed(3, None)).unwrap();
        assert!(fileless.void_owed(&owed(3, None).block_hash).unwrap().is_some());
        assert!(fileless.owed().is_empty());
    }

    #[test]
    fn a_file_less_ledger_tracks_owed_blocks_in_memory() {
        let mut l = Ledger::new(u128::MAX);
        l.record_owed(owed(1, None)).unwrap();
        l.record_owed(owed(1, None)).unwrap();
        assert_eq!(l.owed().len(), 1);
        let settled = l.settle_owed(&owed(1, None).block_hash, 5_000).unwrap().unwrap();
        assert_eq!(settled.settled_at, Some(5_000));
        assert!(l.settle_owed(&hash(0xdead), 5_000).unwrap().is_none());
    }

    pub(super) fn found(n: u64, cumulative_work: u128) -> FoundBlock {
        FoundBlock {
            at: 100 + n,
            height: 961_640 + n as u32,
            block_hash: hash(0xf00_0000 + n),
            paid_to_split: n * 10,
            paid_to_pool: 5,
            finder: "alice".into(),
            tag: "bob".into(),
            difficulty: 100.5,
            cumulative_work,
        }
    }

    #[test]
    fn found_blocks_and_cumulative_work_survive_a_reopen() {
        let scratch = Scratch::new("blocks");
        {
            let (mut l, _) = open(&scratch, u128::MAX, None);
            l.record(1, "alice", 16, &hash(1), "").unwrap();
            l.record(2, "bob", 32, &hash(2), "").unwrap();
            l.record(3, "bob", 32, &hash(2), "").unwrap();
            assert_eq!(l.cumulative_work(), 48);
            l.record_block(found(1, 48)).unwrap();
            l.record_block(FoundBlock { paid_to_pool: 9_999, ..found(1, 48) }).unwrap();
            assert_eq!(l.blocks().len(), 1);
        }
        let (mut l, _) = open(&scratch, u128::MAX, None);
        assert_eq!(l.cumulative_work(), 48, "the counter is read back from the store");
        assert_eq!(l.blocks(), &[found(1, 48)], "the first record is retained");
        l.record(4, "carol", 16, &hash(3), "").unwrap();
        assert_eq!(l.cumulative_work(), 64, "and continues from the stored value");
    }

    #[test]
    fn a_file_less_ledger_counts_cumulative_work_from_its_start() {
        let mut l = Ledger::new(u128::MAX);
        l.record(1, "alice", 16, &hash(1), "").unwrap();
        l.record(2, "alice", 32, &hash(2), "").unwrap();
        assert_eq!(l.cumulative_work(), 48);
        l.record_block(found(1, 48)).unwrap();
        l.record_block(found(1, 48)).unwrap();
        assert_eq!(l.blocks().len(), 1);
    }

    #[test]
    fn work_since_sums_only_the_shares_at_or_after_the_cutoff() {
        let mut l = Ledger::new(u128::MAX);
        l.record(100, "alice", 16, &hash(1), "").unwrap();
        l.record(200, "alice", 16, &hash(2), "").unwrap();
        l.record(200, "bob", 32, &hash(3), "").unwrap();
        let (total, by_identity) = l.work_since(150);
        assert_eq!(total, 48);
        assert_eq!(by_identity.get("alice"), Some(&16));
        assert_eq!(by_identity.get("bob"), Some(&32));
        let (all, _) = l.work_since(0);
        assert_eq!(all, 64, "a cutoff before every share reads the whole window");
        let (none, empty) = l.work_since(300);
        assert_eq!((none, empty.len()), (0, 0), "a cutoff after every share reads none");
        assert_eq!(l.work_since(200).0, 48);
    }
}
