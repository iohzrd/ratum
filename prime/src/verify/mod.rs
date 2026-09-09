//! Whether a submitted share is one the pool credits: the job and coinbase sections a
//! connection has installed, the tip and target it is judged against, and the guard against
//! crediting one share twice. Turning a submission into the header and coinbase it claims
//! is in `rebuild`.

mod rebuild;

use crate::bounded::BoundedSet;
use ratum::datum::abw::SlotKeys;
use ratum::datum::messages::{ClientConfig, CoinbaseOutput, CoinbaserResponse, RejectReason};
use ratum::datum::share::{
    self, COINBASE_ID_SUBSIDY_ONLY, CoinbaseSection, JobSection, MAX_COINBASE_SECTION_BYTES,
    MAX_JOBS, MAX_USERNAME, PowSubmit,
};
use ratum::header;
use ratum::target;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

const MAX_COINBASE_TYPES: u8 = 6;
const MAX_SEEN: usize = 1 << 20;

const MAX_INSTALLED_COINBASE_BYTES: usize = 16 << 20;

/// The block hashes of the shares already credited, so a resend is not credited twice.
#[derive(Debug)]
pub struct ReplayGuard(BoundedSet<[u8; 32]>);

impl ReplayGuard {
    pub fn new(capacity: usize) -> Self {
        Self(BoundedSet::new(capacity))
    }

    pub fn accept(&mut self, hash: [u8; 32]) -> bool {
        self.0.insert(hash)
    }

    pub fn remove(&mut self, hash: &[u8; 32]) -> bool {
        self.0.remove(hash)
    }
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::new(MAX_SEEN)
    }
}

const DEFAULT_NTIME_WINDOW_SECS: u64 = 2 * 60 * 60;

const TIP_GRACE_SECS: u64 = 1;

const SPLIT_GRACE_SECS: u64 = 10;

const MAX_RECENT_TIPS: usize = 3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolPolicy {
    pub payout_script: Vec<u8>,
    pub prime_id: u64,
    pub coinbase_tag: String,
    pub min_difficulty: u64,
    pub ntime_window_secs: u64,
    pub require_split: bool,
}

impl PoolPolicy {
    pub fn from_config(c: &ClientConfig) -> Self {
        Self {
            payout_script: c.payout_script.clone(),
            prime_id: u64::from(c.prime_id),
            coinbase_tag: c.coinbase_tag.clone(),
            min_difficulty: c.min_difficulty,
            ntime_window_secs: DEFAULT_NTIME_WINDOW_SECS,
            require_split: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rebuilt {
    pub difficulty: u64,
    pub block_hash: [u8; 32],
    pub raw_hash: [u8; 32],
    pub job_bits: u32,
    pub header: [u8; header::HEADER_V2_SIZE],
    pub coinbase_tx: Vec<u8>,
    pub height: u32,
    pub txn_count: u32,
    pub coinbaser_id: u8,
    pub paid_to_split: u64,
    pub paid_to_pool: u64,
    pub unpaid: Vec<usize>,
    pub tag_secondary: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted {
    pub work: Rebuilt,
    pub is_block: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AbwKeys {
    pub seeded: SlotKeys,
    pub revealed: SlotKeys,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DictatedSplit {
    pub outputs: Vec<CoinbaseOutput>,
    pub identities: Vec<String>,
    pub sent_at: u64,
}

pub type Splits = HashMap<u8, DictatedSplit>;

#[derive(Clone, Debug)]
struct JobState {
    job: JobSection,
    coinbases: HashMap<u8, CoinbaseSection>,
    parent_seen: bool,
    evicted: bool,
}

impl JobState {
    fn coinbase_bytes(&self) -> usize {
        self.coinbases.values().map(coinbase_bytes).sum()
    }
}

fn coinbase_bytes(cb: &CoinbaseSection) -> usize {
    cb.coinb1.len() + cb.coinb2.len()
}

#[derive(Debug)]
pub struct Verifier {
    policy: PoolPolicy,
    jobs: Vec<Option<JobState>>,
    splits: Splits,
    replay: Arc<Mutex<ReplayGuard>>,
    tip: Option<[u8; 32]>,
    tip_next_target: Option<target::Target>,
    recent_tips: VecDeque<([u8; 32], u64)>,
    installed_coinbase_bytes: usize,
    abw_keys: Option<AbwKeys>,
}

impl Verifier {
    pub fn new(policy: PoolPolicy, replay: Arc<Mutex<ReplayGuard>>) -> Self {
        Self {
            policy,
            jobs: vec![None; MAX_JOBS],
            splits: HashMap::new(),
            replay,
            tip: None,
            tip_next_target: None,
            recent_tips: VecDeque::new(),
            installed_coinbase_bytes: 0,
            abw_keys: None,
        }
    }

    pub fn set_next_target(&mut self, next_bits: Option<u32>) {
        self.tip_next_target = next_bits.and_then(target::bits_to_target);
    }

    pub fn set_abw_keys(&mut self, keys: Option<AbwKeys>) {
        self.abw_keys = keys;
    }

    pub fn record_dictated(
        &mut self,
        response: &CoinbaserResponse,
        identities: Vec<String>,
        now: u64,
    ) {
        self.splits.insert(
            response.coinbaser_id,
            DictatedSplit { outputs: response.outputs.clone(), identities, sent_at: now },
        );
    }

    pub fn take_splits(&mut self) -> Splits {
        std::mem::take(&mut self.splits)
    }

    pub fn restore_splits(&mut self, splits: Splits) {
        self.splits = splits;
    }

    pub fn unpaid_outputs(&self, work: &Rebuilt) -> Vec<(String, u64)> {
        let Some(split) = self.splits.get(&work.coinbaser_id) else {
            return Vec::new();
        };
        work.unpaid
            .iter()
            .filter_map(|&i| {
                let d = split.outputs.get(i)?;
                let identity = split
                    .identities
                    .get(i)
                    .filter(|id| !id.is_empty())
                    .cloned()
                    .unwrap_or_else(|| format!("script {}", hex::encode(&d.script)));
                Some((identity, d.value))
            })
            .collect()
    }

    pub fn set_tip(&mut self, tip: Option<[u8; 32]>, now: u64) {
        if self.tip != tip {
            if let Some(replaced) = self.tip {
                self.recent_tips.push_back((replaced, now));
            }
            while self
                .recent_tips
                .front()
                .is_some_and(|(_, at)| now.saturating_sub(*at) > TIP_GRACE_SECS)
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

    fn meets_network_target(&self, work: &Rebuilt) -> bool {
        self.tip_next_target
            .as_ref()
            .is_some_and(|target| target::meets_target(&work.block_hash, target))
    }

    fn within_tip_grace(&self, prev_hash: [u8; 32], now: u64) -> bool {
        self.recent_tips.iter().any(|(hash, replaced_at)| {
            *hash == prev_hash && now.saturating_sub(*replaced_at) <= TIP_GRACE_SECS
        })
    }

    pub fn reason_for_decode_error(e: &share::Error) -> RejectReason {
        match e {
            share::Error::BadExtranonceSize(_) => RejectReason::BadExtranonceSize,
            share::Error::BadUsername => RejectReason::BadUsername,
            share::Error::BadMerkleCount(_) => RejectReason::BadMerkleCount,
            share::Error::BadBlake2bSection | share::Error::MissingBlake2bSection => {
                RejectReason::BadBlake2bSection
            }
            share::Error::Truncated(_) | share::Error::UnknownSection(_) => RejectReason::Other,
        }
    }

    pub fn verify(&mut self, s: &PowSubmit, now: u64) -> Result<Accepted, RejectReason> {
        let work = self.rebuild(s, now)?;
        let is_block = self.meets_network_target(&work);

        if !ratum::lock(&self.replay).accept(work.block_hash) {
            return Err(RejectReason::DuplicateWork);
        }
        Ok(Accepted { work, is_block })
    }

    pub fn rebuild_refused(&self, s: &PowSubmit) -> Option<Rebuilt> {
        self.build_unchecked(s, true).ok().map(|(work, _, _)| work)
    }

    pub fn block_candidate(&self, work: &Rebuilt) -> bool {
        self.meets_network_target(work) || meets_own_bits(work)
    }

    fn build(&self, s: &PowSubmit) -> Result<(Rebuilt, [u8; 32]), RejectReason> {
        let (work, prev_hash, seeded) = self.build_unchecked(s, false)?;
        if !seeded {
            return Err(RejectReason::BadAbwSlot);
        }

        if self.tip == Some(prev_hash)
            && let Some(node_target) = self.tip_next_target
        {
            let job_target =
                target::bits_to_target(work.job_bits).ok_or(RejectReason::BadTarget)?;
            if job_target > node_target {
                return Err(RejectReason::BadTarget);
            }
        }
        Ok((work, prev_hash))
    }

    fn build_unchecked(
        &self,
        s: &PowSubmit,
        allow_evicted: bool,
    ) -> Result<(Rebuilt, [u8; 32], bool), RejectReason> {
        let (job, cb) = self.resolve(s, allow_evicted)?;
        let (abw_key, seeded) = match &self.abw_keys {
            None => (None, true),
            Some(keys) => {
                let slot = usize::from(s.abw_slot.ok_or(RejectReason::BadAbwSlot)?);
                let seeded = keys.seeded.get(slot).copied().flatten();
                let revealed = keys.revealed.get(slot).copied().flatten();
                match (seeded, revealed) {
                    (Some(key), _) => (Some(key), true),
                    (None, Some(key)) => (Some(key), false),
                    (None, None) => return Err(RejectReason::BadAbwSlot),
                }
            }
        };
        let work = rebuild::build_work(&self.policy, &self.splits, job, cb, s, abw_key)?;
        Ok((work, job.prev_hash, seeded))
    }

    fn check_share(
        &self,
        s: &PowSubmit,
        work: &Rebuilt,
        prev_hash: [u8; 32],
        now: u64,
    ) -> Result<(), RejectReason> {
        if !self.meets_network_target(work)
            && let Some(tip) = self.tip
            && prev_hash != tip
            && !self.within_tip_grace(prev_hash, now)
        {
            return Err(RejectReason::StaleBlock);
        }
        self.check_split(s, work, now)?;
        check_username_and_time(&self.policy, s, now)
    }

    fn check_split(&self, s: &PowSubmit, work: &Rebuilt, now: u64) -> Result<(), RejectReason> {
        if !self.policy.require_split
            || s.subsidy_only
            || work.paid_to_split != 0
            || work.coinbaser_id == 0
            || self.meets_network_target(work)
        {
            return Ok(());
        }
        match self.splits.get(&work.coinbaser_id) {
            Some(split)
                if !split.outputs.is_empty()
                    && now.saturating_sub(split.sent_at) > SPLIT_GRACE_SECS =>
            {
                Err(RejectReason::NoSplit)
            }
            _ => Ok(()),
        }
    }

    fn rebuild(&mut self, s: &PowSubmit, now: u64) -> Result<Rebuilt, RejectReason> {
        let (work, prev_hash) = self.build(s)?;
        let meets = target::meets_target(&work.raw_hash, &target::target_for_pot(s.target_byte));
        if meets || self.meets_network_target(&work) {
            self.install_sections(s)?;
        }
        self.check_share(s, &work, prev_hash, now)?;
        if !meets {
            return Err(RejectReason::HighHash);
        }
        Ok(work)
    }

    fn brings_new_job(&self, s: &PowSubmit) -> bool {
        s.job.as_ref().is_some_and(|job| {
            self.jobs[s.job_id as usize].as_ref().is_none_or(|st| st.job != *job)
        })
    }

    fn resolve<'a>(
        &'a self,
        s: &'a PowSubmit,
        allow_evicted: bool,
    ) -> Result<(&'a JobSection, &'a CoinbaseSection), RejectReason> {
        if s.subsidy_only {
            if s.coinbase_id != COINBASE_ID_SUBSIDY_ONLY {
                return Err(RejectReason::BadCoinbaseId);
            }
        } else if s.coinbase_id >= MAX_COINBASE_TYPES {
            return Err(RejectReason::BadCoinbaseId);
        }
        let slot = self.jobs[s.job_id as usize].as_ref();
        if let Some(st) = slot
            && st.evicted
            && !allow_evicted
            && s.job.as_ref().is_none_or(|job| job.prev_hash == st.job.prev_hash)
        {
            return Err(RejectReason::StaleBlock);
        }
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
                if coinbase_bytes(cb) > MAX_COINBASE_SECTION_BYTES {
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

    fn install_sections(&mut self, s: &PowSubmit) -> Result<(), RejectReason> {
        let idx = s.job_id as usize;
        let new_job = self.brings_new_job(s);
        let released =
            if new_job { self.jobs[idx].as_ref().map_or(0, JobState::coinbase_bytes) } else { 0 };
        if let Some(cb) = &s.coinbase {
            let replaced = if new_job {
                0
            } else {
                self.jobs[idx]
                    .as_ref()
                    .and_then(|st| st.coinbases.get(&cb.coinbase_id))
                    .map_or(0, coinbase_bytes)
            };
            let projected = self.installed_coinbase_bytes.saturating_sub(released + replaced)
                + coinbase_bytes(cb);
            if projected > MAX_INSTALLED_COINBASE_BYTES {
                return Err(RejectReason::CoinbaseTooLarge);
            }
        }
        if new_job {
            let job = s.job.as_ref().expect("new_job requires a job section");
            self.installed_coinbase_bytes = self.installed_coinbase_bytes.saturating_sub(released);
            self.jobs[idx] = Some(JobState {
                job: job.clone(),
                coinbases: HashMap::new(),
                parent_seen: self.parent_kept(job.prev_hash),
                evicted: false,
            });
        }
        if let Some(cb) = &s.coinbase {
            let state = self.jobs[idx].as_mut().expect("resolved against this slot");
            let replaced = state.coinbases.get(&cb.coinbase_id).map_or(0, coinbase_bytes);
            self.installed_coinbase_bytes =
                self.installed_coinbase_bytes.saturating_sub(replaced) + coinbase_bytes(cb);
            state.coinbases.insert(cb.coinbase_id, cb.clone());
        }
        Ok(())
    }
}

fn parent_is_kept(
    tip: Option<[u8; 32]>,
    recent_tips: &VecDeque<([u8; 32], u64)>,
    prev_hash: [u8; 32],
) -> bool {
    tip == Some(prev_hash) || recent_tips.iter().any(|(h, _)| *h == prev_hash)
}

const PRINTABLE_ASCII: std::ops::RangeInclusive<u8> = 0x21..=0x7e;

fn check_username_and_time(
    policy: &PoolPolicy,
    s: &PowSubmit,
    now: u64,
) -> Result<(), RejectReason> {
    if s.username.is_empty()
        || s.username.len() > MAX_USERNAME
        || !s.username.bytes().all(|b| PRINTABLE_ASCII.contains(&b))
        || s.username.starts_with('.')
    {
        return Err(RejectReason::BadUsername);
    }
    let b = &s.blake2b;
    let ntime = if s.use_time_offset {
        let (time_offset, _) = b.time_fields();
        b.time_on_wire.wrapping_add(time_offset)
    } else {
        b.time_on_wire
    };
    if policy.ntime_window_secs != 0 && u64::from(ntime).abs_diff(now) > policy.ntime_window_secs {
        return Err(RejectReason::BadNtime);
    }
    Ok(())
}

fn meets_own_bits(work: &Rebuilt) -> bool {
    target::bits_to_target(work.job_bits)
        .is_some_and(|t| target::meets_target(&work.block_hash, &t))
}
