//! What an accepted share and a found block do to the ledger: the hash claimed so a share is
//! credited once, the share recorded to the window, and the block recorded with whatever its
//! coinbase failed to pay.

use crate::ledger::Share;
use crate::ledger::blocks::{FoundBlock, OwedBlock};
use crate::ledger::split::Payout;
use crate::payout::dictated_outputs;
use crate::server::Server;
use crate::verify::{NTIME_WINDOW_SECS, RebuiltShare, Refusal};
use log::{debug, error, info, warn};
use ratum::datum::messages::share_response::RejectReason;
use ratum::lock;
use ratum::username::address_of;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::Mutex;

/// How far back the pool's clock may step without a hash being forgotten while a resend of its
/// share could still be accepted.
const CLOCK_STEP_MARGIN_SECS: u64 = 10 * ratum::SECS_PER_MINUTE;

/// How long an accepted share's hash is held. A share is accepted only while its header time is
/// within `NTIME_WINDOW_SECS` of the pool's clock, and that time is hashed into the share, so a
/// share accepted at `A` carries a header time of at most `A + NTIME_WINDOW_SECS` and no resend
/// of it passes the same check after `A + 2 × NTIME_WINDOW_SECS`. Holding a hash longer refuses
/// nothing more.
pub const ACCEPTED_HASH_RETENTION_SECS: u64 = 2 * NTIME_WINDOW_SECS + CLOCK_STEP_MARGIN_SECS;

/// The most hashes held however many shares are accepted within `ACCEPTED_HASH_RETENTION_SECS`:
/// the memory bound, about 123 MiB (123 bytes a hash, measured). It covers 69 shares a second
/// for the whole retention; past that the oldest are forgotten early, and a share resent after
/// its hash was forgotten would be credited again.
pub const MAX_ACCEPTED_HASHES: usize = 1 << 20;

/// The block hashes of the shares accepted across every connection within
/// `ACCEPTED_HASH_RETENTION_SECS`, so a share is credited once however many times it is sent.
#[derive(Debug)]
pub struct AcceptedShareHashes {
    /// Each held hash and the time it was accepted at.
    accepted_at: HashMap<[u8; 32], u64>,
    /// Every hash held, in the order it was accepted, including ones removed since. An entry
    /// leaves `accepted_at` only if that map holds the hash under this entry's time, so a hash
    /// removed and accepted again in a later second is kept for its later acceptance; accepted
    /// again in the same second, it leaves with the first of its two entries the cap drops.
    order: VecDeque<(u64, [u8; 32])>,
    capacity: usize,
    warned_capped: bool,
}

impl AcceptedShareHashes {
    pub fn new(capacity: usize) -> Self {
        Self {
            accepted_at: HashMap::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
            warned_capped: false,
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.accepted_at.len()
    }

    /// Holds `hash` as accepted at `now`; false when it is already held.
    pub fn insert(&mut self, hash: [u8; 32], now: u64) -> bool {
        self.hold(hash, now, now)
    }

    /// Holds `hash` as accepted at `at`, a time read back from the ledger; called oldest first.
    pub fn restore(&mut self, hash: [u8; 32], at: u64, now: u64) -> bool {
        self.hold(hash, at, now)
    }

    pub fn remove(&mut self, hash: &[u8; 32]) -> bool {
        self.accepted_at.remove(hash).is_some()
    }

    fn hold(&mut self, hash: [u8; 32], at: u64, now: u64) -> bool {
        self.expire(now);
        if self.accepted_at.contains_key(&hash) {
            return false;
        }
        // Dropped before the new hash is added, so neither `order` nor `accepted_at` grows
        // past the capacity and doubles its buffer.
        let mut forgot_early = false;
        while self.order.len() >= self.capacity {
            let oldest = self.order.pop_front().expect("at the capacity");
            forgot_early |= self.forget(oldest);
        }
        if forgot_early && !self.warned_capped {
            self.warned_capped = true;
            warn!(
                "more share hashes were accepted within {ACCEPTED_HASH_RETENTION_SECS} seconds \
                 than the {} held; the oldest are forgotten before a resend of their share stops \
                 being accepted, so such a resend would be credited again. Raise --min-diff to \
                 accept fewer, larger shares.",
                self.capacity
            );
        }
        self.accepted_at.insert(hash, at);
        self.order.push_back((at, hash));
        true
    }

    fn expire(&mut self, now: u64) {
        while let Some(&(at, hash)) = self.order.front() {
            if at.saturating_add(ACCEPTED_HASH_RETENTION_SECS) >= now {
                break;
            }
            self.order.pop_front();
            self.forget((at, hash));
        }
    }

    /// Removes `hash` from `accepted_at` if it is held there at `at`; true when it was.
    fn forget(&mut self, (at, hash): (u64, [u8; 32])) -> bool {
        if self.accepted_at.get(&hash) == Some(&at) {
            self.accepted_at.remove(&hash);
            true
        } else {
            false
        }
    }
}

/// Claims the share's block hash as accepted at `now`; a hash already claimed refuses the share
/// as duplicate work, with the rebuilt share for its reference.
pub fn claim(
    hashes: &Mutex<AcceptedShareHashes>,
    rebuilt: RebuiltShare,
    now: u64,
) -> Result<RebuiltShare, Refusal> {
    if lock(hashes).insert(rebuilt.block_hash, now) {
        Ok(rebuilt)
    } else {
        Err(Refusal { reason: RejectReason::DuplicateWork, rebuilt: Some(Box::new(rebuilt)) })
    }
}

/// Records the accepted share to the ledger. A share the ledger could not record releases
/// its claim, so a resend can be credited.
pub fn credit_share(
    server: &Server,
    peer: SocketAddr,
    username: &str,
    rebuilt: &RebuiltShare,
    now: u64,
) -> io::Result<()> {
    let share = Share {
        accepted_at: now,
        identity: address_of(username).to_string(),
        difficulty: rebuilt.difficulty,
        block_hash: rebuilt.block_hash,
        tag_secondary: rebuilt.tag_secondary.clone(),
    };
    let removed = match lock(&server.ledger).record(share) {
        Ok(removed) => removed,
        Err(e) => {
            lock(&server.accepted_hashes).remove(&rebuilt.block_hash);
            return Err(e);
        }
    };
    if removed != 0 {
        info!(
            "[{peer}]      ledger retention removed {removed} share(s) past --ledger-keep-shares"
        );
    }
    debug!(
        "[{peer}]   <- accepted diff={} hash={} height={} split={} pool={} sats from {username}",
        rebuilt.difficulty,
        hex::encode(rebuilt.block_hash),
        rebuilt.height,
        rebuilt.paid_to_split,
        rebuilt.paid_to_pool,
    );
    Ok(())
}

/// Records the block to the ledger's history and, when its coinbase left dictated outputs
/// out or paid the window nothing, what the pool's payout script owes for it.
pub fn record_block(
    server: &Server,
    peer: SocketAddr,
    username: &str,
    rebuilt: &RebuiltShare,
    now: u64,
) {
    record_found_block(server, peer, username, rebuilt, now);
    if !rebuilt.unpaid_outputs.is_empty() {
        record_unpaid_outputs(server, peer, rebuilt, now);
    } else if rebuilt.paid_to_split == 0 {
        record_owed_block(server, peer, rebuilt, now);
    }
}

fn identity_suffix(count: usize) -> &'static str {
    if count == 1 { "y" } else { "ies" }
}

fn log_and_record_owed(server: &Server, peer: SocketAddr, owed: OwedBlock) {
    for Payout { identity, sats } in &owed.entries {
        warn!("[{peer}]   **   {identity} {sats} sats");
    }
    let hash = hex::encode(owed.block_hash);
    warn!(
        "[{peer}]   ** recorded as owed by block hash {hash}; after paying it from the \
         pool's wallet, run: ratum-prime --settle-block {hash} (with --ledger or \
         --data-dir, pool stopped)"
    );
    let recorded = lock(&server.records).record_owed(owed);
    if let Err(e) = recorded {
        error!(
            "[{peer}]   !! could not record the owed amounts to the ledger ({e}); they \
             are in this log only"
        );
    }
}

fn record_found_block(
    server: &Server,
    peer: SocketAddr,
    username: &str,
    rebuilt: &RebuiltShare,
    now: u64,
) {
    let network_difficulty = server.node_state.tip().map_or(0.0, |t| t.difficulty);
    let block = FoundBlock {
        found_at: now,
        height: rebuilt.height,
        block_hash: rebuilt.block_hash,
        paid_to_split: rebuilt.paid_to_split,
        paid_to_pool: rebuilt.paid_to_pool,
        finder: address_of(username).to_string(),
        tag_secondary: rebuilt.tag_secondary.clone(),
        network_difficulty,
        cumulative_work: lock(&server.ledger).cumulative_work(),
    };
    if let Err(e) = lock(&server.records).record_block(block) {
        error!(
            "[{peer}]   !! could not record the block to the ledger's history ({e}); the \
             block itself was already relayed"
        );
    }
}

/// The record of `entries` owed against the block of `rebuilt`; none when they total nothing.
fn owed_block(rebuilt: &RebuiltShare, found_at: u64, entries: Vec<Payout>) -> Option<OwedBlock> {
    let owed = OwedBlock {
        found_at,
        height: rebuilt.height,
        block_hash: rebuilt.block_hash,
        settled_at: None,
        entries,
    };
    (owed.total() != 0).then_some(owed)
}

/// A coinbase that paid the window nothing owes the split a coinbaser response would dictate
/// for what the pool's payout script received (`Ledger::split` deducts the operator fee).
fn record_owed_block(server: &Server, peer: SocketAddr, rebuilt: &RebuiltShare, now: u64) {
    let value = rebuilt.paid_to_pool;
    let entries = dictated_outputs(server, value).into_iter().map(|d| d.payout).collect();
    let Some(owed) = owed_block(rebuilt, now, entries) else {
        warn!(
            "[{peer}]   ** the block's {value} sats went to the pool's payout script and \
             the window names nobody to owe them to"
        );
        return;
    };
    warn!(
        "[{peer}]   ** the block's coinbase paid the window nothing; the pool's payout \
         script received {value} sats of which {} are owed to {} identit{}:",
        owed.total(),
        owed.entries.len(),
        identity_suffix(owed.entries.len()),
    );
    log_and_record_owed(server, peer, owed);
}

/// A coinbase that left dictated outputs out owes them, each scaled down in proportion when
/// they total more than the pool's payout script received beyond the operator fee.
fn record_unpaid_outputs(server: &Server, peer: SocketAddr, rebuilt: &RebuiltShare, now: u64) {
    let value = rebuilt.paid_to_split.saturating_add(rebuilt.paid_to_pool);
    let fee = lock(&server.ledger).split_policy().fee_on(value);
    let available = rebuilt.paid_to_pool.saturating_sub(fee);
    let mut entries = rebuilt.unpaid_outputs.clone();
    let dictated: u64 = entries.iter().map(|p| p.sats).sum();
    if dictated > available {
        warn!(
            "[{peer}]   ** the coinbase left out {dictated} sats of dictated outputs but the \
             pool's payout script received only {available} sats beyond the fee; the owed \
             amounts are scaled down to what it received"
        );
        for p in &mut entries {
            p.sats = (u128::from(p.sats) * u128::from(available) / u128::from(dictated)) as u64;
        }
        entries.retain(|p| p.sats > 0);
    }
    let Some(owed) = owed_block(rebuilt, now, entries) else { return };
    warn!(
        "[{peer}]   ** the block's coinbase left out {} of the dictated outputs; the pool's \
         payout script received {} sats of which {} are owed to {} identit{}:",
        rebuilt.unpaid_outputs.len(),
        rebuilt.paid_to_pool,
        owed.total(),
        owed.entries.len(),
        identity_suffix(owed.entries.len()),
    );
    log_and_record_owed(server, peer, owed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{
        ALICE, BOB, payout, server_with, server_with_fee, server_with_public_gateway_fee,
    };

    const PEER: SocketAddr =
        SocketAddr::V4(std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 28915));

    fn block(paid_to_split: u64, paid_to_pool: u64, unpaid_outputs: Vec<Payout>) -> RebuiltShare {
        RebuiltShare {
            is_block: true,
            difficulty: 1,
            block_hash: [0xbb; 32],
            raw_pow_hash: [0xbb; 32],
            prev_hash: [0x5a; 32],
            job_bits: 0x207f_ffff,
            header: [0; ratum::header::HEADER_V2_SIZE],
            coinbase_tx: Vec::new(),
            height: 961_866,
            txn_count: 0,
            coinbaser_id: 1,
            paid_to_split,
            paid_to_pool,
            unpaid_outputs,
            tag_secondary: "garage".into(),
        }
    }

    fn server() -> Server {
        server_with(&[(ALICE, 3), (BOB, 1)], 0)
    }

    fn owed_entries(server: &Server) -> Vec<Vec<Payout>> {
        lock(&server.records).owed().iter().map(|o| o.entries.clone()).collect()
    }

    #[test]
    fn a_block_paying_the_split_is_recorded_and_owes_nothing() {
        let server = server();
        record_block(&server, PEER, "carol.rig", &block(900, 100, Vec::new()), 42);
        let records = lock(&server.records);
        let found = &records.blocks()[0];
        assert_eq!((found.finder.as_str(), found.tag_secondary.as_str()), ("carol", "garage"));
        assert_eq!((found.paid_to_split, found.paid_to_pool, found.found_at), (900, 100, 42));
        assert!(records.owed().is_empty());
    }

    #[test]
    fn a_block_leaving_dictated_outputs_out_owes_them() {
        let server = server();
        let left_out = vec![payout("carol", 60), payout("dave", 20)];
        record_block(&server, PEER, "alice", &block(900, 100, left_out.clone()), 42);
        assert_eq!(lock(&server.records).blocks().len(), 1);
        assert_eq!(owed_entries(&server), [left_out], "not the window's split");
    }

    #[test]
    fn a_block_paying_the_window_nothing_owes_the_window_split() {
        let server = server();
        record_block(&server, PEER, "alice", &block(0, 1_000_000, Vec::new()), 42);
        assert_eq!(lock(&server.records).blocks().len(), 1);
        assert_eq!(owed_entries(&server), [vec![payout(ALICE, 750_000), payout(BOB, 250_000)]]);
    }

    fn server_charging_a_fee() -> Server {
        server_with_fee(&[(ALICE, 3), (BOB, 1)], 0, 100)
    }

    #[test]
    fn left_out_outputs_the_pool_script_received_are_owed_as_dictated() {
        let server = server_charging_a_fee();
        let left_out = vec![payout("alice", 50), payout("bob", 30)];
        record_block(&server, PEER, "alice", &block(900, 100, left_out.clone()), 42);
        let records = lock(&server.records);
        let owed = &records.owed()[0];
        assert_eq!((owed.height, owed.block_hash, owed.found_at), (961_866, [0xbb; 32], 42));
        assert_eq!(owed.settled_at, None);
        assert_eq!(owed.entries, left_out, "80 sats of the 90 left after a 10 sat fee");
    }

    #[test]
    fn left_out_outputs_over_what_the_pool_script_received_are_scaled_down() {
        let server = server_charging_a_fee();
        let left_out = vec![payout("alice", 60), payout("bob", 20)];
        record_block(&server, PEER, "alice", &block(940, 60, left_out), 42);
        assert_eq!(
            owed_entries(&server),
            [vec![payout("alice", 37), payout("bob", 12)]],
            "80 sats scaled to the 50 left after the fee, rounded down"
        );
    }

    #[test]
    fn nothing_is_owed_when_the_pool_script_received_only_the_fee() {
        let server = server_charging_a_fee();
        let left_out = vec![payout("alice", 60), payout("bob", 20)];
        record_block(&server, PEER, "alice", &block(990, 10, left_out), 42);
        assert_eq!(lock(&server.records).blocks().len(), 1);
        assert!(owed_entries(&server).is_empty(), "every amount scales to zero");
    }

    #[test]
    fn a_block_paying_the_window_nothing_owes_the_split_minus_the_fee() {
        let server = server_charging_a_fee();
        record_block(&server, PEER, "alice", &block(0, 1_000_000, Vec::new()), 42);
        assert_eq!(owed_entries(&server), [vec![payout(ALICE, 742_500), payout(BOB, 247_500)]]);
    }

    #[test]
    fn a_block_paying_an_empty_window_nothing_owes_nothing() {
        let server = server_with(&[], 0);
        record_block(&server, PEER, "alice", &block(0, 1_000_000, Vec::new()), 42);
        assert_eq!(lock(&server.records).blocks().len(), 1);
        assert!(owed_entries(&server).is_empty());
    }

    #[test]
    fn the_owed_split_charges_the_public_gateway_fee_and_reassigns_it() {
        let server = server_with_public_gateway_fee(5_000, 10_000);
        record_block(&server, PEER, "alice", &block(0, 200, Vec::new()), 42);
        assert_eq!(owed_entries(&server), [vec![payout(BOB, 150), payout(ALICE, 50)]]);
    }

    #[test]
    fn a_hash_is_claimed_once_and_a_released_one_again() {
        let server = server();
        assert!(claim(&server.accepted_hashes, block(900, 100, Vec::new()), 42).is_ok());
        let refusal = claim(&server.accepted_hashes, block(900, 100, Vec::new()), 42).unwrap_err();
        assert_eq!(refusal.reason, RejectReason::DuplicateWork);
        assert_eq!(refusal.rebuilt.map(|r| r.block_hash), Some([0xbb; 32]));
        lock(&server.accepted_hashes).remove(&[0xbb; 32]);
        assert!(claim(&server.accepted_hashes, block(900, 100, Vec::new()), 42).is_ok());
    }

    #[test]
    fn a_share_recorded_within_the_retention_is_claimed_after_a_restart() {
        use crate::fixtures::{Scratch, server_on, share};
        use crate::ledger::blocks::BlockRecords;
        use crate::ledger::split::SplitPolicy;
        use crate::ledger::{Ledger, WindowRule, open_share_ledger};
        let scratch = Scratch::new("claimed-after-restart");
        let path = scratch.join("regtest.redb");
        let open = || {
            let ledger = Ledger::new(WindowRule::fixed(u128::MAX), SplitPolicy::default());
            open_share_ledger(Some(&path), None, Some("regtest"), ledger).unwrap()
        };
        let now = ratum::unix_now();
        {
            let (mut ledger, _) = open();
            let expired = now - ACCEPTED_HASH_RETENTION_SECS - 1;
            ledger.record(share(expired, ALICE, 1, [1; 32], "")).unwrap();
            ledger.record(share(now, ALICE, 1, [2; 32], "")).unwrap();
        }
        let server = server_on(open().0, BlockRecords::default());
        let again = |hash| RebuiltShare { block_hash: hash, ..block(900, 100, Vec::new()) };
        let refusal = claim(&server.accepted_hashes, again([2; 32]), now).unwrap_err();
        assert_eq!(refusal.reason, RejectReason::DuplicateWork, "accepted before the restart");
        assert!(
            claim(&server.accepted_hashes, again([1; 32]), now).is_ok(),
            "accepted past the retention, so no resend of it passes the time check"
        );
    }

    #[test]
    fn a_hash_is_held_for_the_retention_and_forgotten_after() {
        let mut hashes = AcceptedShareHashes::new(8);
        assert!(hashes.insert([1; 32], 1_000));
        assert!(hashes.insert([2; 32], 1_000 + 60));
        let end = 1_000 + ACCEPTED_HASH_RETENTION_SECS;
        assert!(!hashes.insert([1; 32], end), "held through its last second");
        assert!(hashes.insert([1; 32], end + 1), "and accepted again once it has passed");
        assert!(!hashes.insert([2; 32], end + 1), "the later one is still held");
        assert!(hashes.insert([2; 32], end + 61), "then its own retention passes");
        assert!(!hashes.insert([1; 32], end + 61), "while the re-accepted one is held");
    }

    #[test]
    fn a_hash_removed_and_accepted_again_is_held_from_its_later_acceptance() {
        let mut hashes = AcceptedShareHashes::new(8);
        assert!(hashes.insert([1; 32], 1_000));
        assert!(hashes.remove(&[1; 32]), "released after a failed ledger write");
        assert!(hashes.insert([1; 32], 2_000), "and credited on its resend");
        let first_expiry = 1_000 + ACCEPTED_HASH_RETENTION_SECS + 1;
        assert!(
            !hashes.insert([1; 32], first_expiry),
            "the first acceptance expiring does not release the second"
        );
        assert!(hashes.insert([1; 32], 2_000 + ACCEPTED_HASH_RETENTION_SECS + 1));
    }

    #[test]
    fn restored_hashes_keep_the_time_they_were_accepted_at() {
        let mut hashes = AcceptedShareHashes::new(8);
        let now = 10_000 + ACCEPTED_HASH_RETENTION_SECS;
        assert!(hashes.restore([1; 32], 10_000, now));
        assert!(!hashes.insert([1; 32], now), "held until its own retention ends");
        assert!(hashes.insert([1; 32], now + 1));
    }

    #[test]
    fn past_the_capacity_the_buffers_stay_at_the_capacity() {
        let mut hashes = AcceptedShareHashes::new(64);
        for i in 0..200u8 {
            assert!(hashes.insert([i; 32], 5));
        }
        assert_eq!(hashes.len(), 64);
        let capacity = hashes.order.capacity();
        assert!(capacity < 128, "not doubled past the capacity of 64: {capacity}");
    }

    #[test]
    fn past_the_capacity_the_oldest_hash_is_forgotten() {
        let mut hashes = AcceptedShareHashes::new(2);
        assert!(hashes.insert([1; 32], 5));
        assert!(hashes.insert([2; 32], 5));
        assert!(hashes.insert([3; 32], 5));
        assert_eq!(hashes.len(), 2);
        assert!(hashes.insert([1; 32], 5), "forgotten before its retention ended");
        assert!(!hashes.insert([3; 32], 5));
    }
}
