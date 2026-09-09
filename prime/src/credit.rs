use crate::server::{Payability, Resolver, Server, owed_for_block};
use log::{debug, error, info, warn};
use ratum::datum::share::PowSubmit;
use ratum::lock;
use ratum_prime::ledger;
use ratum_prime::verify::{AcceptedShare, Verifier};
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;

const MAX_CREDITED_NAMES: usize = 4096;

fn identity_suffix(count: usize) -> &'static str {
    if count == 1 { "y" } else { "ies" }
}

pub(crate) struct Crediting {
    peer: SocketAddr,
    credited: HashMap<String, u64>,
    reported_unpayable: HashSet<String>,
}

impl Crediting {
    pub(crate) fn new(peer: SocketAddr) -> Self {
        Self { peer, credited: HashMap::new(), reported_unpayable: HashSet::new() }
    }

    fn log_and_record_owed(&self, server: &Server, owed: ledger::OwedBlock) {
        let peer = self.peer;
        for (identity, sats) in &owed.entries {
            warn!("[{peer}]   **   {identity} {sats} sats");
        }
        let hash = hex::encode(owed.block_hash);
        warn!(
            "[{peer}]   ** recorded as owed by block hash {hash}; after paying it from the \
             pool's wallet, run: ratum-prime --settle-block {hash} (with --ledger or \
             --data-dir, pool stopped)"
        );
        let recorded = lock(&server.ledger).record_owed(owed);
        if let Err(e) = recorded {
            error!(
                "[{peer}]   !! could not record the owed amounts to the ledger ({e}); they \
                 are in this log only"
            );
        }
    }

    pub(crate) fn record_found_block(
        &self,
        server: &Server,
        a: &AcceptedShare,
        s: &PowSubmit,
        now: u64,
    ) {
        let peer = self.peer;
        let difficulty = lock(&server.node_view.tip).map_or(0.0, |t| t.difficulty);
        let mut l = lock(&server.ledger);
        let block = ledger::FoundBlock {
            at: now,
            height: a.work.height,
            block_hash: a.work.block_hash,
            paid_to_split: a.work.paid_to_split,
            paid_to_pool: a.work.paid_to_pool,
            finder: ledger::identity_of(&s.username).to_string(),
            tag: a.work.tag_secondary.clone(),
            difficulty,
            cumulative_work: l.cumulative_work(),
        };
        if let Err(e) = l.record_block(block) {
            error!(
                "[{peer}]   !! could not record the block to the ledger's history ({e}); the \
                 block itself was already relayed"
            );
        }
    }

    pub(crate) fn record_owed_block(&self, server: &Server, a: &AcceptedShare, now: u64) {
        let peer = self.peer;
        let value = a.work.paid_to_pool;
        let Some(owed) = owed_for_block(server, a.work.height, a.work.block_hash, value, now)
        else {
            warn!(
                "[{peer}]   ** the block's {value} sats went to the pool's payout script and \
                 the window names nobody to owe them to"
            );
            return;
        };
        warn!(
            "[{peer}]   ** the block's coinbase paid the window nothing; the pool's payout \
             script received {value} sats of which {} are owed to {} identit{}:",
            owed.total,
            owed.entries.len(),
            identity_suffix(owed.entries.len()),
        );
        self.log_and_record_owed(server, owed);
    }

    pub(crate) fn record_unpaid_outputs(
        &self,
        server: &Server,
        verifier: &Verifier,
        a: &AcceptedShare,
        now: u64,
    ) {
        let peer = self.peer;
        let value = a.work.paid_to_split.saturating_add(a.work.paid_to_pool);
        let fee = server.payout.fee_on(value);
        let available = a.work.paid_to_pool.saturating_sub(fee);
        let mut entries = verifier.unpaid_outputs(&a.work);
        let dictated: u64 = entries.iter().map(|(_, sats)| *sats).sum();
        if dictated > available {
            warn!(
                "[{peer}]   ** the coinbase left out {dictated} sats of dictated outputs but the \
                 pool's payout script received only {available} sats beyond the fee; the owed \
                 amounts are scaled down to what it received"
            );
            for (_, sats) in &mut entries {
                *sats = (u128::from(*sats) * u128::from(available) / u128::from(dictated)) as u64;
            }
            entries.retain(|(_, sats)| *sats > 0);
        }
        let total: u64 = entries.iter().map(|(_, sats)| *sats).sum();
        if total == 0 {
            return;
        }
        warn!(
            "[{peer}]   ** the block's coinbase left out {} of the dictated outputs; the pool's \
             payout script received {} sats of which {total} are owed to {} identit{}:",
            a.work.unpaid.len(),
            a.work.paid_to_pool,
            entries.len(),
            identity_suffix(entries.len()),
        );
        self.log_and_record_owed(
            server,
            ledger::OwedBlock {
                at: now,
                height: a.work.height,
                block_hash: a.work.block_hash,
                total,
                settled_at: None,
                entries,
            },
        );
    }

    pub(crate) fn is_unpayable(&mut self, server: &Server, username: &str) -> bool {
        let identity = ledger::identity_of(username);
        let Payability::Unpayable(why) =
            Resolver::payability(&server.resolver, &server.node, identity)
        else {
            return false;
        };
        let first = self.reported_unpayable.len() < MAX_CREDITED_NAMES
            && self.reported_unpayable.insert(identity.to_string());
        if first {
            warn!(
                "[{}]   <- rejecting shares from {identity:?}, which cannot be paid: {why}. \
                 The gateway sends the miner's own stratum username when \
                 pool_pass_full_users is set; that username must be an address this chain's \
                 node accepts, optionally followed by '.workername'.",
                self.peer
            );
        } else {
            debug!("[{}]   <- rejected: {identity:?} cannot be paid ({why})", self.peer);
        }
        true
    }

    pub(crate) fn record_and_credit(
        &mut self,
        server: &Server,
        s: &PowSubmit,
        a: &AcceptedShare,
        now: u64,
    ) -> io::Result<()> {
        let peer = self.peer;
        let identity = ledger::identity_of(&s.username).to_string();
        let network = lock(&server.node_view.tip).map(|t| t.difficulty);
        {
            let mut l = lock(&server.ledger);
            if let Some(d) = network {
                let w = ledger::window_for_difficulty(
                    d,
                    server.payout.window_multiple,
                    server.payout.window_floor,
                );
                if w != l.window() {
                    let re_read = l.set_window(w);
                    if re_read != 0 {
                        info!(
                            "[{peer}]      difficulty rose; the wider window \
                             re-read {re_read} share(s) from the ledger"
                        );
                    }
                }
            }
            if let Err(e) = l.record(
                now,
                &identity,
                a.work.difficulty,
                &a.work.block_hash,
                &a.work.tag_secondary,
            ) {
                drop(l);
                lock(&server.replay).remove(&a.work.block_hash);
                return Err(e);
            }
            let removed = l.take_removed();
            if removed != 0 {
                info!(
                    "[{peer}]      ledger retention removed {removed} \
                     share(s) past --ledger-keep"
                );
            }
        }
        let total = match self.credited.get_mut(&s.username) {
            Some(total) => {
                *total = total.saturating_add(a.work.difficulty);
                *total
            }
            None => {
                if self.credited.len() < MAX_CREDITED_NAMES {
                    self.credited.insert(s.username.clone(), a.work.difficulty);
                }
                a.work.difficulty
            }
        };
        debug!(
            "[{peer}]   <- accepted diff={} hash={} height={} split={} pool={} sats; {} credited {}",
            a.work.difficulty,
            hex::encode(a.work.block_hash),
            a.work.height,
            a.work.paid_to_split,
            a.work.paid_to_pool,
            s.username,
            total,
        );
        Ok(())
    }
}
