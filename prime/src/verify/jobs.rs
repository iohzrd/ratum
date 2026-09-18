//! The job and coinbase sections one connection has sent: which of them a share is rebuilt on, when
//! a new job replaces them, and the eviction of the jobs whose tip is no longer one the pool
//! credits.

use super::Verifier;
use ratum::datum::messages::share::{
    COINBASE_ID_SUBSIDY_ONLY, CoinbaseSection, JobSection, MAX_COINBASE_SECTION_LEN, PowSubmit,
};
use ratum::datum::messages::share_response::RejectReason;
use std::collections::{HashMap, VecDeque};

pub(super) const MAX_COINBASE_TYPES: u8 = 6;
pub(super) const TIP_GRACE_SECS: u64 = 1;
pub(super) const MAX_RECENT_TIPS: usize = 3;

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
}

impl JobState {
    fn coinbase_bytes(&self) -> usize {
        self.coinbases.values().map(coinbase_bytes).sum()
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
            self.evict_jobs_off_recent_tips();
        }
    }

    fn parent_kept(&self, prev_hash: [u8; 32]) -> bool {
        parent_is_kept(self.tip, &self.recent_tips, prev_hash)
    }

    fn evict_jobs_off_recent_tips(&mut self) {
        let Self { jobs, tip, recent_tips, .. } = self;
        for slot in jobs.iter_mut().flatten() {
            if slot.evicted {
                continue;
            }
            if parent_is_kept(*tip, recent_tips, slot.job.prev_hash) {
                slot.parent_seen = true;
            } else if slot.parent_seen {
                slot.evicted = true;
            }
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
    pub(super) fn install_sections(&mut self, s: &PowSubmit) -> Result<(), RejectReason> {
        let idx = s.job_id as usize;
        let new_job = self.brings_new_job(s);
        let slot = self.jobs[idx].as_ref();
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
            self.jobs[idx] = Some(JobState {
                job: job.clone(),
                coinbases: HashMap::new(),
                parent_seen: self.parent_kept(job.prev_hash),
                evicted: false,
            });
        }
        if let Some(cb) = &s.coinbase {
            let state = self.jobs[idx].as_mut().expect("resolved against this slot");
            state.coinbases.insert(cb.coinbase_id, cb.clone());
        }
        self.installed_coinbase_bytes = projected;
        Ok(())
    }
}
