//! The thread that re-reads each accepted block's confirmations from the node every five minutes,
//! until the block is deep enough, and reports one that leaves the best chain or that the node
//! does not store.

use crate::ledger::blocks::{BlockRecords, ConfirmationReading, OwedBlock};
use crate::server::Server;
use log::{error, info, warn};
use ratum::lock;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const INTERVAL: Duration = Duration::from_secs(5 * ratum::SECS_PER_MINUTE);

const CONFIRMED_DEPTH: i64 = 100;

const MAX_PER_PASS: usize = 32;

pub fn watch(server: Arc<Server>) {
    ratum::thread::spawn("confirmations", move || {
        loop {
            std::thread::sleep(INTERVAL);
            check_once(&server);
        }
    });
}

/// The blocks to read this pass, at most `MAX_PER_PASS`: every block under `CONFIRMED_DEPTH`
/// confirmations, those never read first in the order they were found, then the rest least
/// recently read first. A block that stays under the depth (one off the best chain, or one the
/// node does not store) is read again, but after every other block due, so however many there
/// are, each block under the depth is read within `ceil(due / MAX_PER_PASS)` passes.
fn due(records: &BlockRecords) -> Vec<[u8; 32]> {
    let mut due: Vec<(Option<u64>, [u8; 32])> = records
        .blocks()
        .iter()
        .filter_map(|b| match records.confirmations(&b.block_hash) {
            None => Some((None, b.block_hash)),
            Some(s) if s.confirmations < CONFIRMED_DEPTH => {
                Some((Some(s.checked_at), b.block_hash))
            }
            Some(_) => None,
        })
        .collect();
    // Stable, and `None` orders before every `Some`, so blocks read at the same second, and
    // blocks never read, stay in the order they were found.
    due.sort_by_key(|(checked_at, _)| *checked_at);
    due.into_iter().take(MAX_PER_PASS).map(|(_, hash)| hash).collect()
}

fn check_once(server: &Server) {
    check_blocks(&server.records, ratum::unix_now(), |display| {
        server.node.block_confirmations(display)
    });
}

/// Reads each due block from the node and records the answer as read at `now`: the
/// confirmation count, or `ConfirmationReading::NOT_STORED` when the node stores no block
/// under the hash. A read that fails records nothing, so the block stays first in line, and
/// a block voided while it was read gets no reading.
fn check_blocks<E: std::fmt::Display>(
    records: &Mutex<BlockRecords>,
    now: u64,
    read: impl Fn(&str) -> Result<Option<i64>, E>,
) {
    let pending = due(&lock(records));
    for hash in pending {
        let display = hex::encode(hash);
        let confirmations = match read(&display) {
            Ok(Some(c)) => c,
            Ok(None) => ConfirmationReading::NOT_STORED,
            Err(e) => {
                warn!("could not check block {display} against the best chain: {e}");
                continue;
            }
        };
        let state = ConfirmationReading { checked_at: now, confirmations };
        let mut r = lock(records);
        // Voided (--void-block through the control socket) while the node was read.
        if r.block(&hash).is_none() {
            continue;
        }
        let previous = match r.record_confirmations(hash, state) {
            Ok(previous) => previous,
            Err(e) => {
                warn!("could not record the chain state of block {display} ({e})");
                continue;
            }
        };
        let owed = r.owed().iter().find(|o| o.block_hash == hash).cloned();
        drop(r);
        report(&display, state, previous, owed);
    }
}

/// What the reading says about the block when it is not on the best chain.
fn off_chain_text(display: &str, state: ConfirmationReading) -> String {
    if state.node_stores_block() {
        format!(
            "block {display} is no longer on the best chain (the node answers {} confirmations)",
            state.confirmations
        )
    } else {
        format!(
            "the node stores no block under {display}, which the pool recorded as found, so its \
             coinbase is not on the node's best chain"
        )
    }
}

fn report(
    display: &str,
    state: ConfirmationReading,
    previous: Option<ConfirmationReading>,
    owed: Option<OwedBlock>,
) {
    let was_on_chain = previous.is_none_or(|p| p.on_best_chain());
    if state.on_best_chain() {
        if !was_on_chain {
            info!(
                "block {display} is back on the best chain at {} confirmations",
                state.confirmations
            );
        }
        return;
    }
    let owed_note = match &owed {
        Some(o) if o.settled_at.is_some() => format!(
            ", and its {} sats across {} miner(s) were already settled: that payout is not \
             recoverable from this block",
            o.total(),
            o.entries.len()
        ),
        Some(o) => format!(
            ", so the {} sats owed across {} miner(s) against it are not owed; --void-block \
             {display} removes the block and that record",
            o.total(),
            o.entries.len()
        ),
        None => format!("; --void-block {display} removes the block from the history"),
    };
    if was_on_chain {
        error!("{}{owed_note}", off_chain_text(display, state));
    } else if previous.is_some_and(|p| p.node_stores_block() != state.node_stores_block()) {
        warn!("{}", off_chain_text(display, state));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::blocks::FoundBlock;

    fn hash(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn with_blocks(states: &[(u8, Option<i64>)]) -> BlockRecords {
        let mut l = BlockRecords::default();
        for (n, confirmations) in states {
            l.record_block(FoundBlock {
                found_at: 1_000 + u64::from(*n),
                height: 100 + u32::from(*n),
                block_hash: hash(*n),
                paid_to_split: 1,
                paid_to_pool: 1,
                finder: "alice".into(),
                tag_secondary: String::new(),
                network_difficulty: 1.0,
                cumulative_work: 1,
            })
            .unwrap();
            if let Some(confirmations) = confirmations {
                l.record_confirmations(
                    hash(*n),
                    ConfirmationReading { checked_at: 1, confirmations: *confirmations },
                )
                .unwrap();
            }
        }
        l
    }

    #[test]
    fn a_block_deeper_than_the_confirmed_depth_is_not_read_again() {
        let l = with_blocks(&[
            (1, None),
            (2, Some(0)),
            (3, Some(CONFIRMED_DEPTH - 1)),
            (4, Some(CONFIRMED_DEPTH)),
            (5, Some(CONFIRMED_DEPTH + 1)),
            (6, Some(-1)),
        ]);
        assert_eq!(
            due(&l),
            [hash(1), hash(2), hash(3), hash(6)],
            "never read, at the tip, under the depth, and off the chain are all read again"
        );
    }

    #[test]
    fn a_pass_reads_at_most_max_per_pass_blocks() {
        let states: Vec<(u8, Option<i64>)> =
            (0..MAX_PER_PASS as u8 + 10).map(|n| (n, None)).collect();
        let l = with_blocks(&states);
        assert_eq!(due(&l).len(), MAX_PER_PASS);
        assert_eq!(due(&l)[0], hash(0), "the oldest first, so none is starved");
    }

    #[test]
    fn a_block_never_read_comes_before_every_block_read_and_the_least_recently_read_next() {
        let mut l = with_blocks(&[(1, Some(-1)), (2, Some(5)), (3, None), (4, Some(-1))]);
        let read_at = |checked_at| ConfirmationReading { checked_at, confirmations: -1 };
        l.record_confirmations(hash(1), read_at(300)).unwrap();
        l.record_confirmations(hash(2), read_at(100)).unwrap();
        l.record_confirmations(hash(4), read_at(200)).unwrap();
        assert_eq!(due(&l), [hash(3), hash(2), hash(4), hash(1)]);
    }

    /// More stuck blocks than a pass reads: orphans and blocks the node does not store stay
    /// under the depth forever, and a newer block must still be read, as must every stuck one.
    #[test]
    fn more_blocks_stuck_under_the_depth_than_a_pass_reads_do_not_keep_newer_blocks_from_being_read()
     {
        const STUCK: u8 = MAX_PER_PASS as u8 + 8;
        let stuck: Vec<(u8, Option<i64>)> = (0..STUCK).map(|n| (n, None)).collect();
        let records = Mutex::new(with_blocks(&stuck));
        let orphan_or_absent =
            |display: &str| Ok::<_, String>(display.as_bytes()[1].is_multiple_of(2).then_some(-1));
        check_blocks(&records, 1_000, orphan_or_absent);
        {
            let l = lock(&records);
            let read = (0..STUCK).filter(|n| l.confirmations(&hash(*n)).is_some()).count();
            assert_eq!(read, MAX_PER_PASS, "the first pass reads its limit");
        }
        check_blocks(&records, 1_300, orphan_or_absent);
        {
            let l = lock(&records);
            assert!(
                (0..STUCK).all(|n| l.confirmations(&hash(n)).is_some()),
                "the second pass reads the blocks the first left, not the first pass's again"
            );
            let not_stored = (0..STUCK)
                .filter(|n| !l.confirmations(&hash(*n)).unwrap().node_stores_block())
                .count();
            assert!(not_stored > 0, "a block the node does not store is recorded as such");
            assert!(not_stored < usize::from(STUCK), "as is an orphan");
        }

        lock(&records)
            .record_block(FoundBlock {
                found_at: 9_000,
                height: 900,
                block_hash: hash(0xee),
                paid_to_split: 1,
                paid_to_pool: 1,
                finder: "alice".into(),
                tag_secondary: String::new(),
                network_difficulty: 1.0,
                cumulative_work: 1,
            })
            .unwrap();
        assert_eq!(due(&lock(&records))[0], hash(0xee), "a new block is read at the next pass");
        check_blocks(&records, 1_600, |_| Ok::<_, String>(Some(0)));
        assert_eq!(lock(&records).confirmations(&hash(0xee)).map(|s| s.confirmations), Some(0));

        for pass in 0..4u64 {
            check_blocks(&records, 2_000 + 300 * pass, orphan_or_absent);
        }
        let l = lock(&records);
        let oldest = (0..STUCK).map(|n| l.confirmations(&hash(n)).unwrap().checked_at).min();
        assert!(oldest >= Some(2_000), "every stuck block is read again in turn: {oldest:?}");
    }

    #[test]
    fn a_block_the_node_does_not_store_is_recorded_so_and_is_off_the_best_chain() {
        let records = Mutex::new(with_blocks(&[(1, None)]));
        check_blocks(&records, 1_000, |_| Ok::<_, String>(None));
        let reading = lock(&records).confirmations(&hash(1)).expect("a reading is recorded");
        assert_eq!(reading.checked_at, 1_000);
        assert!(!reading.node_stores_block() && !reading.on_best_chain());
        check_blocks(&records, 1_300, |_| Err::<Option<i64>, _>("the node did not answer"));
        assert_eq!(
            lock(&records).confirmations(&hash(1)),
            Some(reading),
            "a failed read records nothing"
        );
    }

    #[test]
    fn a_pass_records_every_reading_and_does_not_hold_the_records_lock_across_the_loop() {
        let records = Arc::new(Mutex::new(with_blocks(&[(1, None), (2, Some(3))])));
        let (finished, done) = std::sync::mpsc::channel();
        let shared = Arc::clone(&records);
        std::thread::spawn(move || {
            check_blocks(&shared, 1_000, |_| Ok::<_, String>(Some(7)));
            finished.send(()).unwrap();
        });
        done.recv_timeout(Duration::from_secs(5)).expect(
            "the pass did not finish: it locks the records inside the loop, so holding the lock \
             across the loop deadlocks the thread",
        );
        let l = lock(&records);
        assert_eq!(l.confirmations(&hash(1)).map(|s| s.confirmations), Some(7));
        assert_eq!(l.confirmations(&hash(2)).map(|s| s.confirmations), Some(7));
    }

    #[test]
    fn a_block_voided_while_the_node_is_read_gets_no_reading() {
        let records = Mutex::new(with_blocks(&[(1, None), (2, None)]));
        check_blocks(&records, 1_000, |display| {
            if display == hex::encode(hash(1)) {
                lock(&records).void_block(&hash(1)).unwrap();
            }
            Ok::<_, String>(Some(3))
        });
        let l = lock(&records);
        assert_eq!(l.confirmations(&hash(1)), None, "the voided block has no reading");
        assert_eq!(l.confirmations(&hash(2)).map(|s| s.confirmations), Some(3));
    }
}
