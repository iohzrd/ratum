//! The thread that re-reads each accepted block's confirmations from the node every five minutes,
//! until the block is deep enough, and reports one that leaves the best chain.

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

fn due(records: &BlockRecords) -> Vec<[u8; 32]> {
    records
        .blocks()
        .iter()
        .filter(|b| {
            records.confirmations(&b.block_hash).is_none_or(|s| s.confirmations < CONFIRMED_DEPTH)
        })
        .map(|b| b.block_hash)
        .take(MAX_PER_PASS)
        .collect()
}

fn check_once(server: &Server) {
    check_blocks(&server.records, |display| server.node.block_confirmations(display));
}

fn check_blocks<E: std::fmt::Display>(
    records: &Mutex<BlockRecords>,
    read: impl Fn(&str) -> Result<Option<i64>, E>,
) {
    let pending = due(&lock(records));
    for hash in pending {
        let display = hex::encode(hash);
        let confirmations = match read(&display) {
            Ok(Some(c)) => c,
            Ok(None) => {
                warn!(
                    "the node stores no block under {display}, which the pool recorded as found; \
                     it cannot be checked against the best chain"
                );
                continue;
            }
            Err(e) => {
                warn!("could not check block {display} against the best chain: {e}");
                continue;
            }
        };
        let state = ConfirmationReading { checked_at: ratum::unix_now(), confirmations };
        let mut r = lock(records);
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
            ", so the {} sats owed across {} miner(s) against it are not owed; --void-block {display} removes that record",
            o.total(),
            o.entries.len()
        ),
        None => String::new(),
    };
    if was_on_chain {
        error!(
            "block {display} is no longer on the best chain (the node answers {} confirmations){owed_note}",
            state.confirmations
        );
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
    fn a_pass_records_every_reading_and_does_not_hold_the_records_lock_across_the_loop() {
        let records = Arc::new(Mutex::new(with_blocks(&[(1, None), (2, Some(3))])));
        let (finished, done) = std::sync::mpsc::channel();
        let shared = Arc::clone(&records);
        std::thread::spawn(move || {
            check_blocks(&shared, |_| Ok::<_, String>(Some(7)));
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
}
