//! Shares recorded from many connections at once share one ledger commit. A caller queues its
//! share and waits; a caller that finds no commit running takes every queued share (at most
//! `MAX_BATCH`), records them under the ledger lock in one transaction (`Ledger::record_batch`,
//! one fsync), and wakes the others with their results. A share is on disk before its caller
//! returns, as with a commit per share; each commit carries the shares that arrived while the
//! one before it ran, so the commits a drive completes per second bound commits, not shares.

use super::{Ledger, Share};
use ratum::lock;
use std::collections::HashMap;
use std::io;
use std::sync::{Condvar, Mutex, PoisonError};

/// The most shares one commit takes; a caller whose share is past it leads the next commit.
pub const MAX_BATCH: usize = 4096;

#[derive(Default)]
pub struct GroupCommit {
    state: Mutex<State>,
    done: Condvar,
}

#[derive(Default)]
struct State {
    next_ticket: u64,
    queued: Vec<(u64, Share)>,
    /// Whether a caller is recording a batch.
    committing: bool,
    /// Each finished ticket's result: the rows retention removed (given to one ticket of the
    /// batch, so it is reported once), or the error, which `io::Error` cannot clone.
    results: HashMap<u64, Result<usize, String>>,
    /// Commits finished, for the tests to compare with the shares recorded.
    #[cfg(test)]
    commits: u64,
}

impl GroupCommit {
    /// Records `share` to `ledger` in the next commit and returns once it is on disk, with the
    /// rows retention removed in that commit (0 for all but one share of a batch). On an error
    /// no share of the commit is recorded.
    pub fn record(&self, ledger: &Mutex<Ledger>, share: Share) -> io::Result<usize> {
        let mut st = lock(&self.state);
        let ticket = st.next_ticket;
        st.next_ticket += 1;
        st.queued.push((ticket, share));
        loop {
            if let Some(result) = st.results.remove(&ticket) {
                return result.map_err(io::Error::other);
            }
            if st.committing {
                st = self.done.wait(st).unwrap_or_else(PoisonError::into_inner);
                continue;
            }
            st.committing = true;
            let take = st.queued.len().min(MAX_BATCH);
            let (tickets, shares): (Vec<u64>, Vec<Share>) = st.queued.drain(..take).unzip();
            drop(st);
            let mut finish = Finish { group: self, tickets, result: None };
            finish.result = Some(lock(ledger).record_batch(shares).map_err(|e| e.to_string()));
            drop(finish);
            st = lock(&self.state);
        }
    }
}

/// Publishes a batch's result to its tickets and lets the next commit start, also when
/// `record_batch` panics, so no waiting caller waits forever.
struct Finish<'a> {
    group: &'a GroupCommit,
    tickets: Vec<u64>,
    result: Option<Result<usize, String>>,
}

impl Drop for Finish<'_> {
    fn drop(&mut self) {
        let result = self.result.take().unwrap_or_else(|| Err("the ledger commit panicked".into()));
        let mut st = lock(&self.group.state);
        st.committing = false;
        #[cfg(test)]
        {
            st.commits += 1;
        }
        for (i, ticket) in self.tickets.iter().enumerate() {
            let r = match &result {
                Ok(removed) if i == 0 => Ok(*removed),
                Ok(_) => Ok(0),
                Err(e) => Err(e.clone()),
            };
            st.results.insert(*ticket, r);
        }
        drop(st);
        self.group.done.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{Scratch, share};
    use crate::ledger::store::Store;
    use crate::ledger::{SplitPolicy, WindowRule};
    use std::time::{Duration, Instant};

    fn file_ledger(scratch: &Scratch) -> Mutex<Ledger> {
        let mut l = Ledger::new(WindowRule::fixed(u128::MAX), SplitPolicy::default());
        l.attach(Store::open(&scratch.join("regtest.redb"), None, Some("regtest")).unwrap())
            .unwrap();
        Mutex::new(l)
    }

    fn hash_of(n: u64) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&n.to_le_bytes());
        h
    }

    /// Records `per_thread` shares from each of `threads` threads, as that many connections
    /// would; returns the time it took.
    fn record_from_threads(
        ledger: &Mutex<Ledger>,
        group: &GroupCommit,
        threads: u64,
        per_thread: u64,
    ) -> Duration {
        let started = Instant::now();
        std::thread::scope(|s| {
            for t in 0..threads {
                s.spawn(move || {
                    for i in 0..per_thread {
                        let n = t * per_thread + i;
                        let identity = format!("miner{t}");
                        let recorded = group
                            .record(ledger, share(1_000 + n, &identity, 1 + n % 7, hash_of(n), ""));
                        recorded.unwrap();
                    }
                });
            }
        });
        started.elapsed()
    }

    #[test]
    fn shares_from_many_connections_are_each_recorded_once_in_shared_commits() {
        let scratch = Scratch::new("group-commit");
        let ledger = file_ledger(&scratch);
        let group = GroupCommit::default();
        record_from_threads(&ledger, &group, 16, 50);
        let work: u128 = (0..800u64).map(|n| u128::from(1 + n % 7)).sum();
        {
            let l = lock(&ledger);
            assert_eq!((l.len(), l.cumulative_work(), l.total_work()), (800, work, work));
            let (db, _) = l.file().unwrap();
            let mut seen = std::collections::HashSet::new();
            crate::ledger::dump(&db, |s| {
                assert!(seen.insert(s.block_hash), "a share stored twice");
                Ok(())
            })
            .unwrap();
            assert_eq!(seen.len(), 800, "every share is on disk");
        }
        let st = lock(&group.state);
        assert!(st.queued.is_empty() && st.results.is_empty() && !st.committing);
        assert!(st.commits <= 800);
        drop(st);
        drop(ledger);
        // Read back from the file: the same window and counter.
        let again = file_ledger(&scratch);
        let l = lock(&again);
        assert_eq!((l.len(), l.cumulative_work(), l.total_work()), (800, work, work));
    }

    #[test]
    fn a_file_less_ledger_records_through_the_group_too() {
        let ledger = Mutex::new(Ledger::new(WindowRule::fixed(u128::MAX), SplitPolicy::default()));
        let group = GroupCommit::default();
        record_from_threads(&ledger, &group, 4, 25);
        assert_eq!(lock(&ledger).len(), 100);
    }

    #[test]
    #[ignore = "measures commit rates on the drive TMPDIR names; run with --release -- --ignored --nocapture"]
    fn group_commit_rate() {
        for threads in [1u64, 4, 16, 64] {
            let scratch = Scratch::new(&format!("group-commit-rate-{threads}"));
            let ledger = file_ledger(&scratch);
            let group = GroupCommit::default();
            let per_thread = 4096 / threads;
            let elapsed = record_from_threads(&ledger, &group, threads, per_thread);
            let shares = threads * per_thread;
            let commits = lock(&group.state).commits;
            println!(
                "{threads:>3} connection(s): {shares} shares in {commits} commits, {:.2} s, {:.0} shares/s",
                elapsed.as_secs_f64(),
                shares as f64 / elapsed.as_secs_f64()
            );
        }
    }
}
