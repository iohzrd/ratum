//! A submitted share: its verdict, the receipt an anti-block-withholding slot gets, the block
//! relayed when the share is one, and the credit recorded to the ledger.

use super::Connection;
use crate::accounting;
use crate::payout;
use crate::relay;
use crate::verify::{RebuiltShare, Refusal, Verifier};
use log::{debug, error, info, warn};
use ratum::datum::messages;
use ratum::datum::messages::abw::CandidateRef;
use ratum::datum::messages::share::PowSubmit;
use ratum::datum::messages::share_response::{RejectReason, ShareResponse, ShareVerdict};
use ratum::datum::messages::validation::{self, TxnList};
use ratum::username::address_of;
use std::io;

/// The distinct unpayable identities one connection names at warn level. Past this the rest
/// are left at debug, so a gateway sending an unbounded number of bad usernames cannot fill
/// the log.
pub(super) const MAX_REPORTED_UNPAYABLE: usize = 4096;

struct ShareOutcome {
    verdict: ShareVerdict,
    followup_request: Option<Vec<u8>>,
    raw_pow_hash: Option<[u8; 32]>,
}

impl Connection<'_> {
    pub(super) fn on_share(&mut self, plain: &[u8]) -> io::Result<()> {
        let peer = self.peer;
        let (response, followup_request) = match PowSubmit::decode(plain) {
            Ok(s) => {
                debug!("[{peer}]   -> share {}", describe_share(&s));
                if let Some(v3) = &mut self.v3 {
                    v3.abw.note_share();
                }
                let outcome = self.share_outcome(&s, ratum::unix_now())?;
                let abw_ref = outcome
                    .raw_pow_hash
                    .zip(self.abw_slot_of(&s))
                    .map(|(hash, slot)| CandidateRef::new(slot, &hash));
                let response = ShareResponse {
                    verdict: outcome.verdict,
                    nonce: s.nonce,
                    target_byte: s.target_byte,
                    job_id: s.job_id,
                    abw_ref,
                };
                (response, outcome.followup_request)
            }
            Err(e) => {
                warn!("[{peer}]   !! could not decode share: {e}");
                if matches!(
                    e,
                    messages::Error::BadBlake2bSection
                        | messages::Error::MissingBlake2bSection
                        | messages::Error::BadExtranonceSize(_)
                ) {
                    warn!(
                        "[{peer}]      a share this pool cannot read indicates a gateway \
                         built against a different revision of the protocol (an upstream \
                         DATUM gateway sends no BLAKE2b section); the pool and the gateway \
                         are released together"
                    );
                }
                let prefix = PowSubmit::prefix(plain).unwrap_or_default();
                let response = ShareResponse {
                    verdict: ShareVerdict::Rejected(Verifier::reason_for_decode_error(&e)),
                    nonce: prefix.nonce,
                    target_byte: prefix.target_byte,
                    job_id: prefix.job_id,
                    abw_ref: None,
                };
                (response, None)
            }
        };
        self.send_mining(&response.encode(), false)?;
        if let Some(request) = followup_request {
            self.send_mining(&request, false)?;
            info!("[{peer}]   <- requested the block's transactions (0x50 0x12)");
        }
        Ok(())
    }

    fn share_outcome(&mut self, s: &PowSubmit, now: u64) -> io::Result<ShareOutcome> {
        // Not `self.abw()`: the borrow must stay on `v3` alone, beside `verifier` under &mut.
        let abw = self.v3.as_ref().map(|v| &v.abw);
        let verified = self.verifier.verify(s, abw, now);
        match verified.and_then(|rebuilt| accounting::claim(&self.server.accepted_hashes, rebuilt))
        {
            Ok(rebuilt) => self.on_accepted(s, &rebuilt, now),
            Err(refusal) => self.on_refused(s, refusal),
        }
    }

    fn on_accepted(
        &mut self,
        s: &PowSubmit,
        rebuilt: &RebuiltShare,
        now: u64,
    ) -> io::Result<ShareOutcome> {
        let peer = self.peer;
        let raw_pow_hash = Some(rebuilt.raw_pow_hash);
        let candidate = rebuilt.is_block_candidate();
        if rebuilt.is_block {
            warn!(
                "[{peer}]   ** BLOCK at height {}: {}",
                rebuilt.height,
                hex::encode(rebuilt.block_hash)
            );
        } else if candidate {
            info!(
                "[{peer}]      share meets its job's bits {:#010x} but not the node's \
                 next target; not relayed",
                rebuilt.job_bits
            );
        }
        if candidate {
            self.send_abw_receipt(s, rebuilt)?;
        }
        let followup_request = if rebuilt.is_block {
            self.relay_and_record(s, rebuilt, now)
        } else {
            if s.is_block {
                warn!(
                    "[{peer}]   !! gateway flagged a block but the hash does not meet the \
                     network target"
                );
            }
            None
        };
        if self.refuse_if_unpayable(&s.username) {
            let verdict = ShareVerdict::Rejected(RejectReason::BadUsername);
            return Ok(ShareOutcome { verdict, followup_request, raw_pow_hash });
        }
        if let Err(e) = accounting::credit_share(self.server, peer, &s.username, rebuilt, now) {
            error!(
                "[{peer}]   !! could not record the share to the ledger ({e}); it is \
                 not credited and its hash was removed from the accepted share hashes so a \
                 resend can be credited"
            );
        }
        Ok(ShareOutcome { verdict: ShareVerdict::Accepted, followup_request, raw_pow_hash })
    }

    fn refuse_if_unpayable(&mut self, username: &str) -> bool {
        let chain = self.server.share_policy.chain;
        let identity = address_of(username);
        if payout::address_script(identity, chain).is_some() {
            return false;
        }
        let reason = payout::unpayable_reason(chain);
        // The identity is named the first time it is seen, and the explanation of what a
        // username must look like follows it once per connection rather than once per
        // identity: an operator needs to see every miner that is being rejected, not the
        // same paragraph repeated for each of them.
        let explain = self.reported_unpayable.is_empty();
        let unreported = self.reported_unpayable.len() < MAX_REPORTED_UNPAYABLE
            && self.reported_unpayable.insert(identity.to_string());
        if unreported {
            warn!(
                "[{}]   <- rejecting shares from {identity:?}, which cannot be paid: it is \
                 {reason}",
                self.peer
            );
            if explain {
                warn!(
                    "[{}]      The gateway sends the miner's own stratum username when \
                     pool_pass_full_users is set; that username must be such an address, \
                     optionally followed by '.workername'.",
                    self.peer
                );
            }
        } else {
            debug!("[{}]   <- rejected: {identity:?} cannot be paid ({reason})", self.peer);
        }
        true
    }

    fn relay_and_record(
        &mut self,
        s: &PowSubmit,
        rebuilt: &RebuiltShare,
        now: u64,
    ) -> Option<Vec<u8>> {
        let peer = self.peer;
        let mut followup_request = None;
        if !s.subsidy_only && rebuilt.txn_count != 0 {
            info!(
                "[{peer}]      block has {} more transactions; requesting them",
                rebuilt.txn_count
            );
            if let Some(prev) = self.awaiting_txns.insert(s.job_id, rebuilt.clone()) {
                error!(
                    "[{peer}]   !! a block on job {} was still awaiting its transactions \
                     and is abandoned: {}",
                    s.job_id,
                    hex::encode(prev.block_hash)
                );
            }
            followup_request = Some(validation::request_block_txns(s.job_id));
        } else {
            relay::submit(peer, &self.server.node, s.job_id, rebuilt, &[]);
        }
        accounting::record_block(self.server, peer, &s.username, rebuilt, now);
        followup_request
    }

    fn on_refused(&mut self, s: &PowSubmit, refusal: Refusal) -> io::Result<ShareOutcome> {
        let peer = self.peer;
        let Refusal { reason, rebuilt } = refusal;
        debug!("[{peer}]   <- rejected: {reason:?}");
        if let Some(r) = &rebuilt
            && s.is_block
        {
            warn!(
                "[{peer}]   !! pool built header {} coinbase {}",
                hex::encode(r.header),
                hex::encode(&r.coinbase_tx)
            );
        }
        let rebuilt = rebuilt.filter(|_| self.abw_slot_of(s).is_some());
        if let Some(r) = &rebuilt
            && r.is_block_candidate()
        {
            warn!(
                "[{peer}]   ** the refused share ({reason:?}) meets a block \
                 target: sending the ABW receipt so the gateway counts it handled"
            );
            self.send_abw_receipt(s, r)?;
        }
        Ok(ShareOutcome {
            verdict: ShareVerdict::Rejected(reason),
            followup_request: None,
            raw_pow_hash: rebuilt.map(|r| r.raw_pow_hash),
        })
    }

    pub(super) fn on_block_txns(&mut self, plain: &[u8]) {
        let peer = self.peer;
        let selector = plain.get(validation::SELECTOR_AT).copied();
        if selector != Some(validation::response::BLOCK_TXNS) {
            warn!("[{peer}]   !! unhandled 0x50 response {selector:?}");
            return;
        }
        let list = match TxnList::decode(plain, validation::response::BLOCK_TXNS) {
            Ok(b) => b,
            Err(e) => {
                error!("[{peer}]   !! bad block response: {e}");
                return;
            }
        };
        info!(
            "[{peer}]   -> block transactions: job {} {} {} txns",
            list.job_index,
            list.status,
            list.txns.len()
        );
        let Some(rebuilt) = self.awaiting_txns.remove(&list.job_index) else {
            warn!(
                "[{peer}]      transactions for job {} that nothing is waiting on",
                list.job_index
            );
            return;
        };
        if list.status != validation::TxnListStatus::Ok {
            error!("[{peer}]      cannot assemble the block: {}", list.status);
            return;
        }
        relay::submit(peer, &self.server.node, list.job_index, &rebuilt, &list.txns);
    }
}

fn describe_share(s: &PowSubmit) -> String {
    let sections = match (&s.job, &s.coinbase) {
        (Some(j), Some(c)) => format!(
            " +job(h={} {} branches) +coinbase(id={} {}+{}B)",
            j.height,
            j.merkle_branches.len(),
            c.coinbase_id,
            c.coinb1.len(),
            c.coinb2.len()
        ),
        (Some(j), None) => format!(" +job(h={} {} branches)", j.height, j.merkle_branches.len()),
        (None, Some(c)) => format!(" +coinbase(id={})", c.coinbase_id),
        (None, None) => String::new(),
    };
    format!(
        "job={} cb={} diff={} nonce={:08x} ntime={:08x} user={:?}{}{}{}",
        s.job_id,
        s.coinbase_id,
        s.difficulty(),
        s.nonce,
        s.ntime,
        s.username,
        if s.is_block { " is_block" } else { "" },
        if s.quickdiff { " quickdiff" } else { "" },
        sections
    )
}
