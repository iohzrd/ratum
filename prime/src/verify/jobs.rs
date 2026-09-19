//! The job and coinbase sections one connection has sent: which of them a share is rebuilt on, when
//! a new job replaces them, and the eviction of the jobs whose tip is no longer one the pool
//! credits.

use super::Verifier;
use ratum::datum::messages::share::{
    COINBASE_ID_SUBSIDY_ONLY, CoinbaseSection, JobSection, MAX_COINBASE_SECTION_LEN, PowSubmit,
};
use ratum::datum::messages::share_response::RejectReason;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

pub(super) const MAX_COINBASE_TYPES: u8 = 6;
pub(super) const TIP_GRACE_SECS: u64 = 1;
pub(super) const MAX_RECENT_TIPS: usize = 3;

/// How long a job whose parent the pool's node has not reported is kept. A gateway whose node
/// is ahead of the pool's builds on a block the pool reads within seconds; a job whose parent
/// the node never reports builds on a block that is not the node's, and is evicted so its
/// sections are released.
pub(super) const UNSEEN_PARENT_SECS: u64 = 120;

/// The pow hashes of the shares that installed sections, held per connection.
pub(super) const MAX_INSTALLING_SHARES: usize = 4096;

/// The jobs one connection holds transactions for. A gateway serves the priority and the
/// coinbaser job of its tip, and shares on the replaced tip's pair arrive within the tip grace,
/// so four cover an honest gateway; the bound keeps a gateway that installs a job in each of the
/// 256 slots and answers each request with a full frame of transactions from making the pool
/// hold a frame per slot.
pub(super) const MAX_JOBS_HOLDING_TXNS: usize = 4;

/// The node's verdicts one job keeps, one per coinbase its shares were rebuilt on. A gateway
/// sends at most `MAX_COINBASE_TYPES` coinbases a job; past this the verdicts are cleared and
/// the next share of each coinbase is validated again.
const MAX_BLOCK_CHECKS: usize = 64;

/// The transactions of a job, which the pool holds to validate the job's block with the node
/// and to relay a block found on it.
#[derive(Clone, Debug)]
pub enum JobTxns {
    /// Not requested: no share on the job has needed them, or the job has none.
    Unrequested,
    /// Requested from the gateway; the connection holds the request's deadline.
    Requested,
    /// Received and checked against the job's merkle branches.
    Held(Arc<[Arc<[u8]>]>),
    /// Not delivered, or not the job's: every share on the job is refused for the reason.
    Refused(RejectReason),
}

/// The node's verdict on a job's block with one coinbase (`getblocktemplate` proposal mode).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockCheck {
    /// Valid with the header version given; a share with another version outside the rolled
    /// bits is refused.
    Valid {
        version: u32,
    },
    Invalid(RejectReason),
    /// The node did not answer; its shares are refused, and the block is proposed again by a
    /// share arriving at or after `retry_at` (unix seconds).
    Unavailable {
        retry_at: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ReplacedTip {
    pub(super) hash: [u8; 32],
    pub(super) replaced_at: u64,
}

#[derive(Clone, Debug)]
pub(super) struct JobState {
    pub(super) job: JobSection,
    coinbases: HashMap<u8, CoinbaseSection>,
    parent_seen: bool,
    pub(super) evicted: bool,
    installed_at: u64,
    generation: u64,
    txns: JobTxns,
    checks: HashMap<[u8; 32], BlockCheck>,
}

impl JobState {
    fn coinbase_bytes(&self) -> usize {
        self.coinbases.values().map(coinbase_bytes).sum()
    }

    fn evict(&mut self) {
        self.evicted = true;
        self.txns = JobTxns::Unrequested;
        self.checks.clear();
    }
}

pub(super) fn coinbase_bytes(cb: &CoinbaseSection) -> usize {
    cb.coinb1.len() + cb.coinb2.len()
}

fn parent_is_kept(
    tip: Option<[u8; 32]>,
    recent_tips: &VecDeque<ReplacedTip>,
    prev_hash: [u8; 32],
) -> bool {
    tip == Some(prev_hash) || recent_tips.iter().any(|t| t.hash == prev_hash)
}

impl Verifier<'_> {
    pub fn set_tip(&mut self, tip: Option<[u8; 32]>, now: u64) {
        if self.tip != tip {
            if let Some(replaced) = self.tip {
                self.recent_tips.push_back(ReplacedTip { hash: replaced, replaced_at: now });
            }
            while self
                .recent_tips
                .front()
                .is_some_and(|t| now.saturating_sub(t.replaced_at) > TIP_GRACE_SECS)
            {
                self.recent_tips.pop_front();
            }
            while self.recent_tips.len() > MAX_RECENT_TIPS {
                self.recent_tips.pop_front();
            }
        }
        self.tip = tip;
        if tip.is_some() {
            self.evict_jobs_off_recent_tips(now);
        }
    }

    fn parent_kept(&self, prev_hash: [u8; 32]) -> bool {
        parent_is_kept(self.tip, &self.recent_tips, prev_hash)
    }

    /// Whether `prev_hash` is a tip replaced recently enough to be among those kept.
    pub(super) fn recent_tip(&self, prev_hash: [u8; 32]) -> bool {
        self.recent_tips.iter().any(|t| t.hash == prev_hash)
    }

    /// Evicts the jobs whose parent was the tip and no longer is, and the jobs whose parent
    /// the node has not reported within `UNSEEN_PARENT_SECS` of their installation.
    fn evict_jobs_off_recent_tips(&mut self, now: u64) {
        let Self { jobs, tip, recent_tips, .. } = self;
        for slot in jobs.iter_mut().flatten() {
            if slot.evicted {
                continue;
            }
            if parent_is_kept(*tip, recent_tips, slot.job.prev_hash) {
                slot.parent_seen = true;
            } else if slot.parent_seen || now.saturating_sub(slot.installed_at) > UNSEEN_PARENT_SECS
            {
                slot.evict();
            }
        }
    }

    /// The generation of the job installed in the share's slot, when it is the job the share
    /// was rebuilt on: the job section the share carries, or, carrying none, the slot's.
    pub(super) fn installed_generation(&self, s: &PowSubmit) -> Option<u64> {
        let st = self.jobs[s.job_id as usize].as_ref()?;
        s.job.as_ref().is_none_or(|job| *job == st.job).then_some(st.generation)
    }

    fn live_job(&self, job_id: u8, generation: u64) -> Option<&JobState> {
        self.jobs[usize::from(job_id)]
            .as_ref()
            .filter(|st| st.generation == generation && !st.evicted)
    }

    fn live_job_mut(&mut self, job_id: u8, generation: u64) -> Option<&mut JobState> {
        self.jobs[usize::from(job_id)]
            .as_mut()
            .filter(|st| st.generation == generation && !st.evicted)
    }

    /// The job of `generation` in slot `job_id`, while it is installed there and not evicted.
    pub fn job(&self, job_id: u8, generation: u64) -> Option<&JobSection> {
        self.live_job(job_id, generation).map(|st| &st.job)
    }

    pub fn job_txns(&self, job_id: u8, generation: u64) -> Option<&JobTxns> {
        self.live_job(job_id, generation).map(|st| &st.txns)
    }

    /// Sets the job's transactions; false when the job is no longer installed. Past
    /// `MAX_JOBS_HOLDING_TXNS` jobs holding transactions, the oldest are released with their
    /// node verdicts (txids omit witnesses, so transactions sent again are proposed again).
    pub fn set_job_txns(&mut self, job_id: u8, generation: u64, txns: JobTxns) -> bool {
        let holds = matches!(txns, JobTxns::Held(_));
        let set = self.live_job_mut(job_id, generation).map(|st| st.txns = txns).is_some();
        if set && holds {
            self.release_oldest_held_txns();
        }
        set
    }

    fn release_oldest_held_txns(&mut self) {
        let mut holding: Vec<(u64, usize)> = self
            .jobs
            .iter()
            .enumerate()
            .filter_map(|(at, st)| {
                st.as_ref()
                    .filter(|st| matches!(st.txns, JobTxns::Held(_)))
                    .map(|st| (st.generation, at))
            })
            .collect();
        let Some(surplus) = holding.len().checked_sub(MAX_JOBS_HOLDING_TXNS) else { return };
        holding.sort_unstable();
        for &(_, at) in &holding[..surplus] {
            if let Some(st) = self.jobs[at].as_mut() {
                st.txns = JobTxns::Unrequested;
                st.checks.clear();
            }
        }
    }

    pub fn block_check(
        &self,
        job_id: u8,
        generation: u64,
        digest: &[u8; 32],
    ) -> Option<BlockCheck> {
        self.live_job(job_id, generation)?.checks.get(digest).copied()
    }

    pub fn record_block_check(
        &mut self,
        job_id: u8,
        generation: u64,
        digest: [u8; 32],
        check: BlockCheck,
    ) {
        if let Some(st) = self.live_job_mut(job_id, generation) {
            if st.checks.len() >= MAX_BLOCK_CHECKS {
                st.checks.clear();
            }
            st.checks.insert(digest, check);
        }
    }

    pub(super) fn within_tip_grace(&self, prev_hash: [u8; 32], now: u64) -> bool {
        self.recent_tips
            .iter()
            .any(|t| t.hash == prev_hash && now.saturating_sub(t.replaced_at) <= TIP_GRACE_SECS)
    }

    fn brings_new_job(&self, s: &PowSubmit) -> bool {
        s.job.as_ref().is_some_and(|job| {
            self.jobs[s.job_id as usize].as_ref().is_none_or(|st| st.job != *job)
        })
    }

    /// Refuses a coinbase id the share's work cannot carry: subsidy-only work carries
    /// `COINBASE_ID_SUBSIDY_ONLY`, other work an id under `MAX_COINBASE_TYPES`.
    pub(super) fn check_coinbase_id(s: &PowSubmit) -> Result<(), RejectReason> {
        let valid = if s.subsidy_only {
            s.coinbase_id == COINBASE_ID_SUBSIDY_ONLY
        } else {
            s.coinbase_id < MAX_COINBASE_TYPES
        };
        if valid { Ok(()) } else { Err(RejectReason::BadCoinbaseId) }
    }

    /// Whether the share's job builds on a block the node has not reported: the job installed
    /// in the share's slot is not evicted, builds on `prev_hash`, and its parent has never
    /// been the tip or a replaced tip. The connection holds such a share for the node to
    /// report the block (`connection::shares::UNSEEN_PARENT_HOLD`), since a gateway whose
    /// node received the block first builds on it before the pool's node reports it.
    pub fn parent_unseen(&self, s: &PowSubmit, prev_hash: [u8; 32]) -> bool {
        self.jobs[usize::from(s.job_id)]
            .as_ref()
            .is_some_and(|st| !st.evicted && !st.parent_seen && st.job.prev_hash == prev_hash)
    }

    /// Whether the share names an evicted job, rather than bringing a new job on another tip
    /// into the evicted slot.
    pub(super) fn names_evicted_job(&self, s: &PowSubmit) -> bool {
        self.jobs[s.job_id as usize].as_ref().is_some_and(|st| {
            st.evicted && s.job.as_ref().is_none_or(|job| job.prev_hash == st.job.prev_hash)
        })
    }

    /// The job and coinbase sections the share is rebuilt on: the ones it carries, or the
    /// ones installed in its slot. An evicted job still resolves.
    pub(super) fn resolve<'a>(
        &'a self,
        s: &'a PowSubmit,
    ) -> Result<(&'a JobSection, &'a CoinbaseSection), RejectReason> {
        let slot = self.jobs[s.job_id as usize].as_ref();
        let new_job = self.brings_new_job(s);
        let job = match (&s.job, slot) {
            (Some(job), _) if new_job => job,
            (_, Some(st)) => &st.job,
            (_, None) => return Err(RejectReason::BadJobId),
        };
        let cb = match &s.coinbase {
            Some(cb) => {
                if cb.coinbase_id != s.coinbase_id {
                    return Err(RejectReason::CoinbaseIdMismatch);
                }
                if coinbase_bytes(cb) > MAX_COINBASE_SECTION_LEN {
                    return Err(RejectReason::CoinbaseTooLarge);
                }
                cb
            }
            None => slot
                .filter(|_| !new_job)
                .and_then(|st| st.coinbases.get(&s.coinbase_id))
                .ok_or(RejectReason::CoinbaseMissing)?,
        };
        Ok((job, cb))
    }

    /// Installs the share's job and coinbase sections into its slot. A new job releases
    /// the slot's coinbases; a coinbase replaces the one of its id. The projected total of
    /// installed coinbase bytes must stay under the cap, or nothing is installed.
    pub(super) fn install_sections(
        &mut self,
        s: &PowSubmit,
        raw_pow_hash: [u8; 32],
        now: u64,
    ) -> Result<(), RejectReason> {
        let idx = s.job_id as usize;
        let new_job = self.brings_new_job(s);
        let slot = self.jobs[idx].as_ref();
        let new_coinbase = s.coinbase.as_ref().is_some_and(|cb| {
            new_job || slot.and_then(|st| st.coinbases.get(&cb.coinbase_id)) != Some(cb)
        });
        let changes_slot = new_job || new_coinbase;
        if changes_slot && self.installed_by.contains(&raw_pow_hash) {
            return Err(RejectReason::DuplicateWork);
        }
        let released = if new_job { slot.map_or(0, JobState::coinbase_bytes) } else { 0 };
        let replaced = match &s.coinbase {
            Some(cb) if !new_job => {
                slot.and_then(|st| st.coinbases.get(&cb.coinbase_id)).map_or(0, coinbase_bytes)
            }
            _ => 0,
        };
        let added = s.coinbase.as_ref().map_or(0, coinbase_bytes);
        let projected = self.installed_coinbase_bytes.saturating_sub(released + replaced) + added;
        if s.coinbase.is_some() && projected > self.installed_coinbase_bytes_cap {
            return Err(RejectReason::CoinbaseTooLarge);
        }
        if new_job {
            let job = s.job.as_ref().expect("new_job requires a job section");
            let generation = self.next_generation;
            self.next_generation += 1;
            self.jobs[idx] = Some(JobState {
                job: job.clone(),
                coinbases: HashMap::new(),
                parent_seen: self.parent_kept(job.prev_hash),
                evicted: false,
                installed_at: now,
                generation,
                txns: JobTxns::Unrequested,
                checks: HashMap::new(),
            });
        }
        if let Some(cb) = &s.coinbase {
            let state = self.jobs[idx].as_mut().expect("resolved against this slot");
            state.coinbases.insert(cb.coinbase_id, cb.clone());
        }
        self.installed_coinbase_bytes = projected;
        if changes_slot {
            self.installed_by.insert(raw_pow_hash);
        }
        if self.tip.is_some() {
            self.evict_jobs_off_recent_tips(now);
        }
        Ok(())
    }
}
