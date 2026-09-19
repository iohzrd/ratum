//! A submitted share: its verdict, the receipt an anti-block-withholding slot gets, the block
//! relayed when the share is one, and the credit recorded to the ledger.
//!
//! No share is credited on a job whose block the node has not validated. The first share on a job
//! that carries transactions makes the pool request them (0x50 0x12), before any share on the job
//! can be known to be a block, and the shares on the job are held until they arrive; the node then
//! checks the job's block with each coinbase its shares use (`getblocktemplate` proposal mode,
//! every consensus rule but the proof of work). A gateway that withholds the transactions, or
//! builds a job the node refuses, has none of its shares on that job credited, and a block found
//! on a validated job is relayed from the transactions the pool already holds.

use super::Connection;
use crate::accounting;
use crate::payout;
use crate::relay::{self, Relayed};
use crate::txns;
use crate::verify::{
    self, BlockCheck, JobTxns, NTIME_WINDOW_SECS, RebuiltShare, Refusal, VERSION_ROLLING_MASK,
    Verifier,
};
use log::{debug, error, warn};
use ratum::datum::messages;
use ratum::datum::messages::abw::CandidateRef;
use ratum::datum::messages::share::PowSubmit;
use ratum::datum::messages::share_response::{RejectReason, ShareResponse, ShareVerdict};
use ratum::datum::messages::validation::{self, TxnList};
use ratum::username::address_of;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The distinct unpayable identities one connection names at warn level. Past this the rest
/// are left at debug, so a gateway sending an unbounded number of bad usernames cannot fill
/// the log.
pub(super) const MAX_REPORTED_UNPAYABLE: usize = 4096;

/// How long a gateway has to send a job's transactions once the pool requested them. Its
/// shares on the job wait this long at most for their answer, inside the 25 to 30 seconds a
/// gateway waits for an accepted share before it reconnects.
pub(super) const TXNS_TIMEOUT: Duration = Duration::from_secs(20);

/// The transaction requests one connection has outstanding. A gateway serves one job at a
/// time and replaces it every few tens of seconds, so a request per job is outstanding for
/// about one round trip; a share on a further job is refused rather than requested.
const MAX_TXN_REQUESTS: usize = 8;

/// The shares one connection may have held for their job's transactions or parent: 200 a
/// second over `TXNS_TIMEOUT`. A share past it is refused.
const MAX_HELD_SHARES: usize = 4096;

/// How long a share on a block the node has not reported is held for the node to report it,
/// before it is refused as stale: the gateway's node received the block first, and the pool's
/// node reports it once it propagates, within a few seconds.
pub(super) const UNSEEN_PARENT_HOLD: Duration = Duration::from_secs(10);

/// How long a node that did not answer a proposal is not asked again for that job's block
/// with that coinbase; its shares are refused meanwhile.
const PROPOSAL_RETRY_SECS: u64 = 10;

/// The log lines of each kind below that one connection writes at warn level; the rest are
/// written at debug, so a gateway sending such shares without limit cannot fill the log.
const MAX_WARNED: u32 = 16;

/// What a held share waits for.
enum Awaiting {
    /// Its job's transactions.
    Txns,
    /// The node to report its job's parent, until the instant.
    Parent { until: Instant },
}

/// A share held until its job's transactions arrive, as verified and claimed on arrival, or
/// until the node reports its job's parent, as refused on arrival and verified again on
/// release; the generation of the job it was verified on, and when it arrived.
pub(super) struct HeldShare {
    s: PowSubmit,
    verified: Result<RebuiltShare, Refusal>,
    generation: u64,
    received_at: u64,
    awaiting: Awaiting,
}

impl HeldShare {
    /// The block hash the share claimed on arrival, when it verified.
    pub(super) fn claimed_hash(&self) -> Option<[u8; 32]> {
        self.verified.as_ref().ok().map(|rebuilt| rebuilt.block_hash)
    }

    /// The block hash the share rebuilt to, claimed or not.
    fn hash(&self) -> Option<[u8; 32]> {
        match &self.verified {
            Ok(rebuilt) => Some(rebuilt.block_hash),
            Err(refusal) => refusal.rebuilt.as_ref().map(|rebuilt| rebuilt.block_hash),
        }
    }

    pub(super) fn awaits_parent(&self) -> bool {
        matches!(self.awaiting, Awaiting::Parent { .. })
    }

    /// When the share's wait for its parent ends; none for a share held for its transactions.
    pub(super) fn parent_hold_until(&self) -> Option<Instant> {
        match self.awaiting {
            Awaiting::Parent { until } => Some(until),
            Awaiting::Txns => None,
        }
    }
}

/// A request for a job's transactions: the job's slot and generation, and when it was sent.
pub(super) struct TxnRequest {
    job_id: u8,
    generation: u64,
    sent_at: Instant,
}

impl TxnRequest {
    pub(super) fn deadline(&self) -> Instant {
        self.sent_at + TXNS_TIMEOUT
    }
}

/// How many lines of each rate-limited kind this connection has written at warn level.
#[derive(Default)]
pub(super) struct WarnCounts {
    undecodable: u32,
    refused_blocks: u32,
}

fn warn_level(count: &mut u32) -> log::Level {
    *count = count.saturating_add(1);
    if *count <= MAX_WARNED { log::Level::Warn } else { log::Level::Debug }
}

/// What the node's view of a share's job decides about the share.
enum JobVerdict {
    /// Nothing: the share is refused and is not a block, so the job's validity does not
    /// change its answer.
    NotNeeded,
    /// Its job's transactions are awaited; the share is held under the job's generation.
    Pending(u64),
    /// The job's block with the share's coinbase is valid; the job's transactions, to relay
    /// the share if it is a block.
    Valid(Arc<[Arc<[u8]>]>),
    /// The job's transactions, for a refused share that is a block by its job's bits: the
    /// block is relayed and the node decides, but the share is not credited.
    RelayOnly(Arc<[Arc<[u8]>]>),
    /// The job cannot be credited: its transactions did not arrive or are not the job's, or
    /// the node refused its block.
    Invalid(RejectReason),
    /// The node gave no verdict on the job's block, or found its parent no longer the tip:
    /// the share is refused for the reason, and is relayed with the job's transactions if it
    /// is a block, so the node decides it.
    Unchecked(RejectReason, Arc<[Arc<[u8]>]>),
}

enum Txns {
    Ready(Arc<[Arc<[u8]>]>),
    Pending,
    Refused(RejectReason),
}

struct ShareOutcome {
    verdict: ShareVerdict,
    raw_pow_hash: Option<[u8; 32]>,
}

fn no_txns() -> Arc<[Arc<[u8]>]> {
    Arc::from(Vec::new())
}

/// The node's verdict on a job's block from its answer to the proposal, and whether it holds
/// for every share on the job with that coinbase. A verdict on the header's own time or
/// version holds for the share proposed alone, since each share carries its own.
fn block_check_from(
    proposal: Result<Option<String>, ratum::rpc::Error>,
    version: u32,
    now: u64,
) -> (BlockCheck, bool) {
    let reason = match proposal {
        Ok(None) => return (BlockCheck::Valid { version }, true),
        Ok(Some(reason)) => reason,
        Err(_) => {
            return (
                BlockCheck::Unavailable { retry_at: now.saturating_add(PROPOSAL_RETRY_SECS) },
                true,
            );
        }
    };
    let (reject, whole_job) = match reason.as_str() {
        "duplicate" => return (BlockCheck::Valid { version }, true),
        // The node holds the block's header but has not yet validated its transactions, as
        // while it fetches a block the gateway submitted to its own node: asked again later.
        "duplicate-inconclusive" => {
            return (
                BlockCheck::Unavailable { retry_at: now.saturating_add(PROPOSAL_RETRY_SECS) },
                true,
            );
        }
        "inconclusive-not-best-prevblk" => (RejectReason::StaleBlock, true),
        "bad-diffbits" => (RejectReason::BadTarget, true),
        "bad-header-height" | "bad-cb-height" => (RejectReason::HeaderFieldMismatch, true),
        "bad-txnmrklroot" | "bad-txns-duplicate" => (RejectReason::HeaderMerkleMismatch, true),
        r if r.starts_with("time-") => (RejectReason::BadNtime, false),
        r if r.starts_with("bad-version") => (RejectReason::BadVersion, false),
        r if r.starts_with("bad-cb-") => (RejectReason::BadCoinbase, true),
        _ => (RejectReason::Other, true),
    };
    (BlockCheck::Invalid(reject), whole_job)
}

impl Connection<'_> {
    pub(super) fn on_share(&mut self, plain: &[u8]) -> io::Result<()> {
        let s = match PowSubmit::decode(plain) {
            Ok(s) => s,
            Err(e) => return self.on_undecodable_share(plain, &e),
        };
        debug!("[{}]   -> share {}", self.peer, describe_share(&s));
        let now = ratum::unix_now();
        let verified = self.verify_and_claim(&s, now);
        self.settle(s, verified, now, Some(Instant::now() + UNSEEN_PARENT_HOLD))
    }

    /// Verifies the share against this connection's jobs, splits and tip, and claims its
    /// hash across every connection.
    fn verify_and_claim(&mut self, s: &PowSubmit, now: u64) -> Result<RebuiltShare, Refusal> {
        // Not `self.abw()`: the borrow must stay on `v3` alone, beside `verifier` under &mut.
        let abw = self.v3.as_ref().map(|v| &v.abw);
        self.verifier
            .verify(s, abw, now)
            .and_then(|rebuilt| accounting::claim(&self.server.accepted_hashes, rebuilt, now))
    }

    fn on_undecodable_share(&mut self, plain: &[u8], e: &messages::Error) -> io::Result<()> {
        let peer = self.peer;
        let level = warn_level(&mut self.warned.undecodable);
        log::log!(level, "[{peer}]   !! could not decode share: {e}");
        if level == log::Level::Warn
            && matches!(
                e,
                messages::Error::BadBlake2bSection
                    | messages::Error::MissingBlake2bSection
                    | messages::Error::BadExtranonceSize(_)
            )
        {
            warn!(
                "[{peer}]      a share this pool cannot read indicates a gateway built against a \
                 different revision of the protocol (an upstream DATUM gateway sends no BLAKE2b \
                 section); the pool and the gateway are released together"
            );
        }
        let prefix = PowSubmit::prefix(plain).unwrap_or_default();
        let response = ShareResponse {
            verdict: ShareVerdict::Rejected(Verifier::reason_for_decode_error(e)),
            nonce: prefix.nonce,
            target_byte: prefix.target_byte,
            job_id: prefix.job_id,
            abw_ref: None,
        };
        self.send_mining(&response.encode(), false)
    }

    /// Answers the share, or holds it while its job's transactions are awaited, or, until
    /// `parent_hold`, while the node has not reported its job's parent.
    fn settle(
        &mut self,
        s: PowSubmit,
        verified: Result<RebuiltShare, Refusal>,
        received_at: u64,
        parent_hold: Option<Instant>,
    ) -> io::Result<()> {
        let verified = match verified {
            // A resend of a held share gets no reference, which would precede the held answer.
            Err(Refusal {
                reason: RejectReason::DuplicateWork | RejectReason::StaleBlock,
                rebuilt: Some(r),
            }) if self.holds(&r.block_hash) => {
                Err(Refusal { reason: RejectReason::DuplicateWork, rebuilt: None })
            }
            Err(Refusal { reason: RejectReason::StaleBlock, rebuilt: Some(r) })
                if parent_hold.is_some_and(|until| Instant::now() < until)
                    && r.job_generation.is_some()
                    && self.verifier.parent_unseen(&s, r.prev_hash) =>
            {
                let generation = r.job_generation.expect("checked in the guard");
                let prev_hash = r.prev_hash;
                let refusal = Refusal { reason: RejectReason::StaleBlock, rebuilt: Some(r) };
                if self.held.len() >= MAX_HELD_SHARES {
                    warn!(
                        "[{}]   !! {MAX_HELD_SHARES} shares already wait for their jobs' \
                         transactions or parent; refusing another",
                        self.peer
                    );
                    Err(refusal)
                } else {
                    debug!(
                        "[{}]      holding a share on block {}, which the node has not reported",
                        self.peer,
                        ratum::bitcoin::hash_to_display_hex(&prev_hash)
                    );
                    let until = parent_hold.expect("checked in the guard");
                    let awaiting = Awaiting::Parent { until };
                    self.held.push(HeldShare {
                        s,
                        verified: Err(refusal),
                        generation,
                        received_at,
                        awaiting,
                    });
                    return Ok(());
                }
            }
            verified => verified,
        };
        let verdict = match self.job_verdict(&s, &verified, received_at) {
            Ok(verdict) => verdict,
            Err(e) => {
                // The write of the transaction request failed and the connection ends with the
                // share unanswered: its hash is released, as a held share's is, so the gateway
                // can replay it on its next connection.
                if let Ok(rebuilt) = &verified {
                    ratum::lock(&self.server.accepted_hashes).remove(&rebuilt.block_hash);
                }
                return Err(e);
            }
        };
        match verdict {
            JobVerdict::Pending(generation) if self.held.len() < MAX_HELD_SHARES => {
                let awaiting = Awaiting::Txns;
                self.held.push(HeldShare { s, verified, generation, received_at, awaiting });
                Ok(())
            }
            JobVerdict::Pending(_) => {
                warn!(
                    "[{}]   !! {MAX_HELD_SHARES} shares already wait for their jobs' \
                     transactions or parent; refusing another",
                    self.peer
                );
                self.answer(&s, verified, JobVerdict::Invalid(RejectReason::Other), received_at)
            }
            verdict => self.answer(&s, verified, verdict, received_at),
        }
    }

    fn job_verdict(
        &mut self,
        s: &PowSubmit,
        verified: &Result<RebuiltShare, Refusal>,
        now: u64,
    ) -> io::Result<JobVerdict> {
        // A resend of a block is relayed only if the node never answered its submission.
        let (rebuilt, credited) = match verified {
            Ok(rebuilt) => (rebuilt, true),
            Err(Refusal { reason, rebuilt: Some(rebuilt) })
                if self.verifier.relayable(rebuilt)
                    && (*reason != RejectReason::DuplicateWork
                        || !ratum::lock(&self.server.relayed_blocks)
                            .contains(&rebuilt.block_hash)) =>
            {
                (rebuilt.as_ref(), false)
            }
            Err(_) => return Ok(JobVerdict::NotNeeded),
        };
        let refused =
            |reason| if credited { JobVerdict::Invalid(reason) } else { JobVerdict::NotNeeded };
        let Some(generation) = rebuilt.job_generation else {
            return Ok(refused(RejectReason::StaleBlock));
        };
        let txns = match self.job_txns(s, generation)? {
            Txns::Ready(txns) => txns,
            Txns::Pending => return Ok(JobVerdict::Pending(generation)),
            Txns::Refused(reason) => return Ok(refused(reason)),
        };
        if !credited {
            return Ok(JobVerdict::RelayOnly(txns));
        }
        let digest = rebuilt.coinbase_digest;
        let check = match self.verifier.block_check(s.job_id, generation, &digest) {
            Some(BlockCheck::Unavailable { retry_at }) if now >= retry_at => {
                self.check_block(s, rebuilt, generation, &txns, now)
            }
            Some(check) => check,
            None => self.check_block(s, rebuilt, generation, &txns, now),
        };
        Ok(match check {
            BlockCheck::Valid { version }
                if (version ^ rebuilt.version) & !VERSION_ROLLING_MASK != 0 =>
            {
                JobVerdict::Invalid(RejectReason::BadVersion)
            }
            BlockCheck::Valid { .. } => JobVerdict::Valid(txns),
            // "inconclusive-not-best-prevblk": the tip moved while the share waited for its
            // job's transactions, and a block on the replaced tip may still win its height.
            BlockCheck::Invalid(RejectReason::StaleBlock) => {
                JobVerdict::Unchecked(RejectReason::StaleBlock, txns)
            }
            BlockCheck::Invalid(reason) => JobVerdict::Invalid(reason),
            BlockCheck::Unavailable { .. } => JobVerdict::Unchecked(RejectReason::Other, txns),
        })
    }

    /// The transactions of the share's job: none for a job that carries none (a subsidy-only
    /// share's block holds the coinbase alone), those held, or a request for them.
    fn job_txns(&mut self, s: &PowSubmit, generation: u64) -> io::Result<Txns> {
        let Some(job) = self.verifier.job(s.job_id, generation) else {
            return Ok(Txns::Refused(RejectReason::StaleBlock));
        };
        if s.subsidy_only || job.txn_count == 0 {
            return Ok(Txns::Ready(no_txns()));
        }
        match self.verifier.job_txns(s.job_id, generation) {
            Some(JobTxns::Held(txns)) => Ok(Txns::Ready(Arc::clone(txns))),
            Some(JobTxns::Requested) => Ok(Txns::Pending),
            Some(JobTxns::Refused(reason)) => Ok(Txns::Refused(*reason)),
            None => Ok(Txns::Refused(RejectReason::StaleBlock)),
            Some(JobTxns::Unrequested) if self.txn_requests.len() >= MAX_TXN_REQUESTS => {
                warn!(
                    "[{}]   !! {MAX_TXN_REQUESTS} transaction requests are outstanding; \
                     refusing a share on job {}",
                    self.peer, s.job_id
                );
                Ok(Txns::Refused(RejectReason::Other))
            }
            Some(JobTxns::Unrequested) => {
                self.send_mining(&validation::request_block_txns(s.job_id), false)?;
                self.verifier.set_job_txns(s.job_id, generation, JobTxns::Requested);
                let sent_at = Instant::now();
                self.txn_requests.push_back(TxnRequest { job_id: s.job_id, generation, sent_at });
                debug!(
                    "[{}]   <- requested the transactions of job {} (0x50 0x12)",
                    self.peer, s.job_id
                );
                Ok(Txns::Pending)
            }
        }
    }

    /// Asks the node for its verdict on the job's block with the share's coinbase and records
    /// it for the other shares on that coinbase.
    fn check_block(
        &mut self,
        s: &PowSubmit,
        rebuilt: &RebuiltShare,
        generation: u64,
        txns: &[Arc<[u8]>],
        now: u64,
    ) -> BlockCheck {
        let proposal = relay::propose(&self.server.node, rebuilt, txns);
        if let Err(e) = &proposal {
            error!(
                "[{}]   !! the node did not answer the proposal of job {}'s block ({e}); its \
                 shares are refused until it does",
                self.peer, s.job_id
            );
        }
        let (check, whole_job) = block_check_from(proposal, rebuilt.version, now);
        match check {
            BlockCheck::Valid { .. } => {
                debug!("[{}]      the node validated job {}'s block", self.peer, s.job_id);
            }
            BlockCheck::Invalid(reason) => warn!(
                "[{}]   !! the node refused job {}'s block at height {} ({reason:?}); \
                 {} not credited",
                self.peer,
                s.job_id,
                rebuilt.height,
                if whole_job { "no share on it is" } else { "this share is" }
            ),
            BlockCheck::Unavailable { .. } => {}
        }
        if whole_job {
            self.verifier.record_block_check(s.job_id, generation, rebuilt.coinbase_digest, check);
        }
        check
    }

    fn answer(
        &mut self,
        s: &PowSubmit,
        verified: Result<RebuiltShare, Refusal>,
        verdict: JobVerdict,
        received_at: u64,
    ) -> io::Result<()> {
        let outcome = match (verified, verdict) {
            (Ok(rebuilt), JobVerdict::Valid(txns)) => {
                self.on_accepted(s, &rebuilt, &txns, received_at)?
            }
            (Ok(rebuilt), verdict) => {
                let (reason, txns) = match verdict {
                    JobVerdict::Invalid(reason) => (reason, None),
                    JobVerdict::Unchecked(reason, txns) => (reason, Some(txns)),
                    _ => (RejectReason::Other, None),
                };
                // Under an assignment the hash stays claimed (`may_reference`).
                if self.abw_slot_of(s).is_none() {
                    ratum::lock(&self.server.accepted_hashes).remove(&rebuilt.block_hash);
                }
                let relay = txns.as_deref().filter(|_| rebuilt.meets_own_bits());
                let refusal = Refusal { reason, rebuilt: Some(Box::new(rebuilt)) };
                self.on_refused(s, refusal, relay, received_at)?
            }
            (Err(refusal), JobVerdict::RelayOnly(txns)) => {
                self.on_refused(s, refusal, Some(&txns), received_at)?
            }
            (Err(refusal), _) => self.on_refused(s, refusal, None, received_at)?,
        };
        let abw_ref = outcome
            .raw_pow_hash
            .zip(self.abw_slot_of(s))
            .map(|(hash, slot)| CandidateRef::new(slot, &hash));
        let response = ShareResponse {
            verdict: outcome.verdict,
            nonce: s.nonce,
            target_byte: s.target_byte,
            job_id: s.job_id,
            abw_ref,
        };
        self.send_mining(&response.encode(), false)
    }

    fn on_accepted(
        &mut self,
        s: &PowSubmit,
        rebuilt: &RebuiltShare,
        txns: &[Arc<[u8]>],
        now: u64,
    ) -> io::Result<ShareOutcome> {
        let peer = self.peer;
        let raw_pow_hash = Some(rebuilt.raw_pow_hash);
        if rebuilt.meets_own_bits() {
            warn!(
                "[{peer}]   ** BLOCK at height {}: {}",
                rebuilt.height,
                hex::encode(rebuilt.block_hash)
            );
        } else if s.is_block {
            warn!(
                "[{peer}]   !! gateway flagged a block but the hash does not meet its job's bits"
            );
        }
        // The block is relayed and the share credited before the receipt is written, so a
        // failed write to the gateway, which ends the connection, loses neither: under an
        // anti-block-withholding assignment the pool is the only submitter of the block, and a
        // replay of a share whose hash stayed claimed would be refused as duplicate work.
        if rebuilt.meets_own_bits() {
            self.relay_and_record(s, rebuilt, txns, now);
        }
        if let Some(v3) = &mut self.v3 {
            v3.abw.note_share();
        }
        let verdict = self.credit(s, rebuilt, now);
        if rebuilt.is_block_candidate() {
            self.send_abw_receipt(s, rebuilt)?;
        }
        Ok(ShareOutcome { verdict, raw_pow_hash })
    }

    /// Records the share's credit, or refuses it when its identity cannot be paid or the ledger
    /// cannot record it.
    fn credit(&mut self, s: &PowSubmit, rebuilt: &RebuiltShare, now: u64) -> ShareVerdict {
        if self.refuse_if_unpayable(&s.username) {
            return ShareVerdict::Rejected(RejectReason::BadUsername);
        }
        let peer = self.peer;
        if let Err(e) = accounting::credit_share(self.server, peer, &s.username, rebuilt, now) {
            error!(
                "[{peer}]   !! could not record the share to the ledger ({e}); it is not \
                 credited, and is answered as refused"
            );
            return ShareVerdict::Rejected(RejectReason::Other);
        }
        ShareVerdict::Accepted
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

    /// Relays the block and, unless the node refused it, records it with what its coinbase
    /// owes: a block the node refused paid nobody.
    fn relay_and_record(
        &mut self,
        s: &PowSubmit,
        rebuilt: &RebuiltShare,
        txns: &[Arc<[u8]>],
        now: u64,
    ) {
        if !ratum::lock(&self.server.relayed_blocks).insert(rebuilt.block_hash) {
            debug!(
                "[{}]      block {} was already submitted to the node; not submitted again",
                self.peer,
                hex::encode(rebuilt.block_hash)
            );
            return;
        }
        match relay::submit(self.peer, &self.server.node, s.job_id, rebuilt, txns) {
            Relayed::Rejected(reason) => warn!(
                "[{}]      the block is not recorded as found: the node refused it ({reason})",
                self.peer
            ),
            Relayed::Accepted => {
                self.note_published_slot(s);
                accounting::record_block(self.server, self.peer, &s.username, rebuilt, now);
            }
            Relayed::Unknown => {
                // The node did not answer: a resend submits the block again (`job_verdict`).
                self.note_published_slot(s);
                ratum::lock(&self.server.relayed_blocks).remove(&rebuilt.block_hash);
                accounting::record_block(self.server, self.peer, &s.username, rebuilt, now);
            }
        }
    }

    /// The relayed block's header carries its slot's key (`AbwSlotState::note_published`).
    fn note_published_slot(&mut self, s: &PowSubmit) {
        let (Some(slot), Some(v3)) = (self.abw_slot_of(s), &mut self.v3) else { return };
        let Some(active) = v3.abw.note_published(slot) else { return };
        warn!(
            "[{}]      the block carries the key of ABW slot {slot}, which is public from now on: \
             shares on the slot are refused{}",
            self.peer,
            if active { ", and the assignment rotates to a new slot" } else { "" }
        );
    }

    fn on_refused(
        &mut self,
        s: &PowSubmit,
        refusal: Refusal,
        relay: Option<&[Arc<[u8]>]>,
        received_at: u64,
    ) -> io::Result<ShareOutcome> {
        let peer = self.peer;
        let Refusal { reason, rebuilt } = refusal;
        debug!("[{peer}]   <- rejected: {reason:?}");
        if let Some(r) = &rebuilt
            && s.is_block
        {
            let level = warn_level(&mut self.warned.refused_blocks);
            log::log!(
                level,
                "[{peer}]   !! refused a share the gateway flagged as a block ({reason:?})"
            );
            debug!(
                "[{peer}]      pool built header {} coinbase {}",
                hex::encode(r.header),
                hex::encode(&r.coinbase_tx)
            );
        }
        if let (Some(r), Some(txns)) = (&rebuilt, relay) {
            warn!(
                "[{peer}]   ** BLOCK at height {} on a refused share ({reason:?}); relaying it, \
                 the share is not credited: {}",
                r.height,
                hex::encode(r.block_hash)
            );
            self.relay_and_record(s, r, txns, received_at);
        }
        let rebuilt = rebuilt.filter(|r| self.may_reference(s, r, received_at));
        if let Some(r) = &rebuilt
            && r.is_block_candidate()
        {
            debug!(
                "[{peer}]   ** the refused share ({reason:?}) meets a block target: sending the \
                 ABW receipt so the gateway counts it handled"
            );
            self.send_abw_receipt(s, r)?;
        }
        Ok(ShareOutcome {
            verdict: ShareVerdict::Rejected(reason),
            raw_pow_hash: rebuilt.map(|r| r.raw_pow_hash),
        })
    }

    /// Whether a refused share's answer may reference it (and so tell the gateway whether it is
    /// a block). Claims its hash so a resend cannot be credited; false past the ntime window.
    fn may_reference(&self, s: &PowSubmit, rebuilt: &RebuiltShare, received_at: u64) -> bool {
        if self.abw_slot_of(s).is_none() {
            return false;
        }
        if !verify::meets_share_target(s, rebuilt) {
            return true;
        }
        if u64::from(s.block_time()) > received_at.saturating_add(NTIME_WINDOW_SECS) {
            return false;
        }
        ratum::lock(&self.server.accepted_hashes).insert(rebuilt.block_hash, received_at);
        true
    }

    /// Whether a share held here for its job's transactions or parent rebuilt to `hash`.
    fn holds(&self, hash: &[u8; 32]) -> bool {
        self.held.iter().any(|h| h.hash().as_ref() == Some(hash))
    }

    /// A job's transactions (0x50 0x92): checked against the job's merkle branches and held,
    /// or the job refused; then the shares held for them are answered.
    pub(super) fn on_block_txns(&mut self, plain: &[u8]) -> io::Result<()> {
        let peer = self.peer;
        let selector = plain.get(validation::SELECTOR_AT).copied();
        if selector != Some(validation::response::BLOCK_TXNS) {
            warn!("[{peer}]   !! unhandled 0x50 response {selector:?}");
            return Ok(());
        }
        let list = match TxnList::decode(plain, validation::response::BLOCK_TXNS) {
            Ok(b) => b,
            Err(e) => {
                warn!("[{peer}]   !! malformed transactions response: {e}");
                return Ok(());
            }
        };
        let Some(at) = self.txn_requests.iter().position(|r| r.job_id == list.job_index) else {
            warn!(
                "[{peer}]      transactions for job {} that no request is waiting on",
                list.job_index
            );
            return Ok(());
        };
        let request = self.txn_requests.remove(at).expect("the position is in range");
        debug!(
            "[{peer}]   -> transactions of job {}: {} {} txns",
            list.job_index,
            list.status,
            list.txns.len()
        );
        let Some(job) = self.verifier.job(request.job_id, request.generation) else {
            return self.release_held(|h| h.s.job_id == request.job_id);
        };
        let txns = if list.status == validation::TxnListStatus::Ok {
            let txns = txns::intern_all(&self.server.txn_cache, list.txns);
            match relay::txns_match_job(&txns, job.txn_count, &job.merkle_branches) {
                Ok(()) => JobTxns::Held(txns),
                Err(why) => {
                    warn!(
                        "[{peer}]   !! job {}: {why}; no share on it is credited",
                        list.job_index
                    );
                    JobTxns::Refused(RejectReason::HeaderMerkleMismatch)
                }
            }
        } else {
            warn!(
                "[{peer}]   !! the gateway sent no transactions for job {} ({}); no share on it \
                 is credited",
                list.job_index, list.status
            );
            JobTxns::Refused(RejectReason::Other)
        };
        self.verifier.set_job_txns(request.job_id, request.generation, txns);
        self.release_held(|h| h.s.job_id == request.job_id && h.generation == request.generation)
    }

    /// Refuses the jobs whose transactions did not arrive within `TXNS_TIMEOUT` of their
    /// request, and answers the shares held for them.
    pub(super) fn expire_txn_requests(&mut self) -> io::Result<()> {
        let now = Instant::now();
        while let Some(at) = self.txn_requests.iter().position(|r| now >= r.deadline()) {
            let request = self.txn_requests.remove(at).expect("the position is in range");
            warn!(
                "[{}]   !! the gateway did not send the transactions of job {} within {}s; no \
                 share on it is credited",
                self.peer,
                request.job_id,
                TXNS_TIMEOUT.as_secs()
            );
            self.verifier.set_job_txns(
                request.job_id,
                request.generation,
                JobTxns::Refused(RejectReason::Other),
            );
            self.release_held(|h| {
                h.s.job_id == request.job_id && h.generation == request.generation
            })?;
        }
        Ok(())
    }

    /// Answers the held shares whose job is no longer installed: another job replaced it in
    /// its slot, or it was evicted with its tip.
    pub(super) fn answer_orphaned_held(&mut self) -> io::Result<()> {
        let verifier = &self.verifier;
        let orphaned: Vec<(u8, u64)> = self
            .held
            .iter()
            .filter(|h| verifier.job(h.s.job_id, h.generation).is_none())
            .map(|h| (h.s.job_id, h.generation))
            .collect();
        for (job_id, generation) in orphaned {
            self.release_held(|h| h.s.job_id == job_id && h.generation == generation)?;
        }
        Ok(())
    }

    /// Refuses the shares whose parent the node has not reported within `UNSEEN_PARENT_HOLD`
    /// of their arrival, by settling them again past their hold.
    pub(super) fn expire_parent_holds(&mut self) -> io::Result<()> {
        let now = Instant::now();
        let due = |h: &HeldShare| h.parent_hold_until().is_some_and(|until| now >= until);
        if !self.held.iter().any(due) {
            return Ok(());
        }
        self.release_held(due)
    }

    /// Settles again, in the order they arrived, the held shares `matches` selects: a share
    /// held for its job's transactions as it was verified on arrival, and a share held for
    /// its job's parent verified anew against the tip now held, its hold kept while the
    /// parent is still unreported and the hold has not passed.
    pub(super) fn release_held(&mut self, matches: impl Fn(&HeldShare) -> bool) -> io::Result<()> {
        let (released, kept): (Vec<HeldShare>, Vec<HeldShare>) =
            std::mem::take(&mut self.held).into_iter().partition(|h| matches(h));
        self.held = kept;
        for HeldShare { s, verified, received_at, awaiting, .. } in released {
            match awaiting {
                Awaiting::Txns => self.settle(s, verified, received_at, None)?,
                Awaiting::Parent { until } => {
                    let verified = self.verify_and_claim(&s, ratum::unix_now());
                    self.settle(s, verified, received_at, Some(until))?;
                }
            }
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_nodes_reasons_map_to_reject_codes_and_header_reasons_hold_for_one_share() {
        let check = |reason: &str| block_check_from(Ok(Some(reason.to_string())), 7, 100);
        assert_eq!(block_check_from(Ok(None), 7, 100), (BlockCheck::Valid { version: 7 }, true));
        assert_eq!(check("duplicate"), (BlockCheck::Valid { version: 7 }, true));
        assert_eq!(check("bad-diffbits"), (BlockCheck::Invalid(RejectReason::BadTarget), true));
        assert_eq!(
            check("bad-header-height"),
            (BlockCheck::Invalid(RejectReason::HeaderFieldMismatch), true)
        );
        assert_eq!(check("bad-cb-amount"), (BlockCheck::Invalid(RejectReason::BadCoinbase), true));
        assert_eq!(
            check("inconclusive-not-best-prevblk"),
            (BlockCheck::Invalid(RejectReason::StaleBlock), true)
        );
        assert_eq!(check("time-too-old"), (BlockCheck::Invalid(RejectReason::BadNtime), false));
        assert_eq!(
            check("bad-version(0x00000001)"),
            (BlockCheck::Invalid(RejectReason::BadVersion), false)
        );
        assert_eq!(check("bad-blk-weight"), (BlockCheck::Invalid(RejectReason::Other), true));
        assert_eq!(
            check("duplicate-inconclusive"),
            (BlockCheck::Unavailable { retry_at: 100 + PROPOSAL_RETRY_SECS }, true)
        );
        let unanswered = block_check_from(Err(ratum::rpc::Error::BadResponse("x".into())), 7, 100);
        assert_eq!(
            unanswered,
            (BlockCheck::Unavailable { retry_at: 100 + PROPOSAL_RETRY_SECS }, true)
        );
    }
}
