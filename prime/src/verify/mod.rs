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

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotKey {
    Secret,
    Revealed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RebuiltShare {
    pub difficulty: u64,
    pub block_hash: [u8; 32],
    pub raw_hash: [u8; 32],
    pub prev_hash: [u8; 32],
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
pub struct AcceptedShare {
    pub work: RebuiltShare,
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
    cap: usize,
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
            cap: MAX_INSTALLED_COINBASE_BYTES,
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

    pub fn unpaid_outputs(&self, work: &RebuiltShare) -> Vec<(String, u64)> {
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

    fn meets_network_target(&self, work: &RebuiltShare) -> bool {
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

    pub fn verify(&mut self, s: &PowSubmit, now: u64) -> Result<AcceptedShare, RejectReason> {
        let work = self.rebuild(s, now)?;
        let is_block = self.meets_network_target(&work);

        if !ratum::lock(&self.replay).accept(work.block_hash) {
            return Err(RejectReason::DuplicateWork);
        }
        Ok(AcceptedShare { work, is_block })
    }

    pub fn rebuild_refused(&self, s: &PowSubmit) -> Option<RebuiltShare> {
        self.build_unchecked(s, true).ok().map(|(work, _)| work)
    }

    pub fn block_candidate(&self, work: &RebuiltShare) -> bool {
        self.meets_network_target(work) || meets_own_bits(work)
    }

    fn build(&self, s: &PowSubmit) -> Result<RebuiltShare, RejectReason> {
        let (work, key) = self.build_unchecked(s, false)?;
        if key == SlotKey::Revealed {
            return Err(RejectReason::BadAbwSlot);
        }

        if self.tip == Some(work.prev_hash)
            && let Some(node_target) = self.tip_next_target
        {
            let job_target =
                target::bits_to_target(work.job_bits).ok_or(RejectReason::BadTarget)?;
            if job_target > node_target {
                return Err(RejectReason::BadTarget);
            }
        }
        Ok(work)
    }

    fn build_unchecked(
        &self,
        s: &PowSubmit,
        allow_evicted: bool,
    ) -> Result<(RebuiltShare, SlotKey), RejectReason> {
        let (job, cb) = self.resolve(s, allow_evicted)?;
        let (abw_key, key) = match &self.abw_keys {
            None => (None, SlotKey::Secret),
            Some(keys) => {
                let slot = usize::from(s.abw_slot.ok_or(RejectReason::BadAbwSlot)?);
                let seeded = keys.seeded.get(slot).copied().flatten();
                let revealed = keys.revealed.get(slot).copied().flatten();
                match (seeded, revealed) {
                    (Some(key), _) => (Some(key), SlotKey::Secret),
                    (None, Some(key)) => (Some(key), SlotKey::Revealed),
                    (None, None) => return Err(RejectReason::BadAbwSlot),
                }
            }
        };
        let work = rebuild::build_work(&self.policy, &self.splits, job, cb, s, abw_key)?;
        Ok((work, key))
    }

    fn check_share(
        &self,
        s: &PowSubmit,
        work: &RebuiltShare,
        now: u64,
    ) -> Result<(), RejectReason> {
        if !self.meets_network_target(work)
            && let Some(tip) = self.tip
            && work.prev_hash != tip
            && !self.within_tip_grace(work.prev_hash, now)
        {
            return Err(RejectReason::StaleBlock);
        }
        self.check_split(s, work, now)?;
        check_username_and_time(&self.policy, s, now)
    }

    fn check_split(
        &self,
        s: &PowSubmit,
        work: &RebuiltShare,
        now: u64,
    ) -> Result<(), RejectReason> {
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

    #[cfg(test)]
    fn reconstruct(&self, s: &PowSubmit, now: u64) -> Result<RebuiltShare, RejectReason> {
        let work = self.build(s)?;
        self.check_share(s, &work, now)?;
        Ok(work)
    }

    fn rebuild(&mut self, s: &PowSubmit, now: u64) -> Result<RebuiltShare, RejectReason> {
        let work = self.build(s)?;
        let meets = target::meets_target(&work.raw_hash, &target::target_for_pot(s.target_byte));
        if meets || self.meets_network_target(&work) {
            self.install_sections(s)?;
        }
        self.check_share(s, &work, now)?;
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
            if projected > self.cap {
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

fn meets_own_bits(work: &RebuiltShare) -> bool {
    target::bits_to_target(work.job_bits)
        .is_some_and(|t| target::meets_target(&work.block_hash, &t))
}

#[cfg(test)]
mod tests {
    use super::rebuild::{Payments, build_header_v2, check_outputs, decode_tag, locate_pot_byte};
    use super::*;
    use ratum::bitcoin::{self, CoinbaseTx};
    use ratum::header::HeaderV2;

    fn verifier() -> Verifier {
        Verifier::new(policy(), Arc::new(Mutex::new(ReplayGuard::default())))
    }
    use ratum::bitcoin::TxOut;

    #[test]
    fn build_header_v2_inverts_from_header_and_share_extranonce() {
        let mut extranonce = [0u8; 16];
        extranonce[4..].copy_from_slice(&[7u8; 12]);
        let h = HeaderV2 {
            version: 0x2000_0000,
            prev_block: [0xaa; 32],
            merkle_root: [0xbb; 32],
            time: 1_700_000_100,
            bits: 0x207f_ffff,
            nonce: 1,
            nonce2: 2,
            nonce3: 3,
            extranonce,
            time_offset: 4,
            txcount: 1,
            flags: header::FLAG_USE_TIME_OFFSET,
            height: 21,
            ..Default::default()
        };
        let job = JobSection {
            prev_hash: h.prev_block,
            target_byte_index: 0,
            nbits: h.bits.to_le_bytes(),
            coinbaser_id: 0,
            height: 21,
            coinbase_value: 0,
            txn_count: 0,
            txn_total_weight: 0,
            txn_total_size: 0,
            txn_total_sigops: 0,
            merkle_branches: vec![],
        };
        let b = share::Blake2bSection::from_header(&h);
        let s = PowSubmit {
            job_id: 0,
            coinbase_id: 0,
            is_block: false,
            subsidy_only: true,
            quickdiff: false,
            target_byte: 10,
            ntime: b.time_on_wire,
            nonce: h.nonce,
            version: header::V2_FLAG | h.version as u32,
            extranonce: share::share_extranonce(&h.extranonce).unwrap(),
            username: String::new(),
            use_time_offset: h.flags & header::FLAG_USE_TIME_OFFSET != 0,
            job: None,
            coinbase: None,
            blake2b: b,
            abw_slot: None,
        };
        assert_eq!(build_header_v2(&job, &s, &b, &h.merkle_root, None).unwrap(), h);
    }

    const NOW: u64 = 1_760_000_000;
    const NBITS: [u8; 4] = [0xff, 0xff, 0x7f, 0x20];
    const COINBASE_VALUE: u64 = 312_500_000;

    const EXTRANONCE: [u8; share::EXTRANONCE_SIZE] = [0x33; share::EXTRANONCE_SIZE];
    const HARD_NBITS: [u8; 4] = [0xff, 0xff, 0x00, 0x1c];
    const DIFF1_NONCE: u32 = 0x099c_1d0f;
    const DIFF1_NTIME_OFFSET: u32 = 0;
    const DIFF1_NONCE_HARD: u32 = 0x5823_2ac6;
    const DIFF1_NTIME_OFFSET_HARD: u32 = 0;

    fn policy() -> PoolPolicy {
        PoolPolicy {
            payout_script: p2wpkh(0xee),
            prime_id: 0x0000_0001,
            coinbase_tag: "RATUM".to_string(),
            min_difficulty: 1,
            ntime_window_secs: DEFAULT_NTIME_WINDOW_SECS,
            require_split: true,
        }
    }

    use ratum::fixtures::{self, Tagging, p2wpkh};

    fn coinbase_sections(p: &PoolPolicy, outputs: &[CoinbaseOutput]) -> (CoinbaseSection, usize) {
        let tagging =
            Tagging { tag: &p.coinbase_tag, tag_secondary: "", prime_id: p.prime_id as u32 };
        fixtures::coinbase(&tagging, &p.payout_script, outputs, COINBASE_VALUE)
    }

    fn job_section(pot_index: usize) -> JobSection {
        JobSection {
            prev_hash: [0x5a; 32],
            target_byte_index: pot_index as u16,
            nbits: NBITS,
            coinbaser_id: 1,
            height: 840_000,
            coinbase_value: COINBASE_VALUE,
            txn_count: 0,
            txn_total_weight: 0,
            txn_total_size: 0,
            txn_total_sigops: 0,
            merkle_branches: vec![],
        }
    }

    fn split() -> CoinbaserResponse {
        CoinbaserResponse {
            value: COINBASE_VALUE,
            coinbaser_id: 1,
            outputs: vec![
                CoinbaseOutput { value: 100_000_000, script: p2wpkh(0x01) },
                CoinbaseOutput { value: 50_000_000, script: p2wpkh(0x02) },
            ],
        }
    }

    fn section(time_on_wire: u32, nonce: u32) -> share::Blake2bSection {
        let mut sia_nonce = [0u8; 8];
        sia_nonce[..4].copy_from_slice(&nonce.to_le_bytes());
        share::Blake2bSection { sia_ntime: [0u8; 8], sia_nonce, time_on_wire }
    }

    fn share_on(job: JobSection, cb: CoinbaseSection) -> PowSubmit {
        let time_on_wire = NOW as u32 + DIFF1_NTIME_OFFSET;
        PowSubmit {
            job_id: 0,
            coinbase_id: 0,
            is_block: false,
            subsidy_only: false,
            quickdiff: false,
            target_byte: 0,
            ntime: time_on_wire,
            nonce: DIFF1_NONCE,
            version: header::V2_FLAG | 0x2000_0000,
            extranonce: EXTRANONCE.to_vec(),
            username: "bc1qexample.worker1".to_string(),
            use_time_offset: false,
            job: Some(job),
            coinbase: Some(cb),
            blake2b: section(time_on_wire, DIFF1_NONCE),
            abw_slot: None,
        }
    }

    fn setup() -> (Verifier, PowSubmit) {
        with_outputs(&split().outputs)
    }

    #[test]
    fn a_coinbase_without_the_split_is_refused_after_the_grace() {
        let build = |coinbaser_id: u8, require_split: bool| {
            let mut p = policy();
            p.require_split = require_split;
            let (cb, pot_index) = coinbase_sections(&p, &[]);
            let mut v = Verifier::new(p, Arc::new(Mutex::new(ReplayGuard::default())));
            v.record_dictated(&split(), Vec::new(), NOW);
            v.set_next_target(Some(u32::from_le_bytes(HARD_NBITS)));
            let mut job = job_section(pot_index);
            job.coinbaser_id = coinbaser_id;
            (v, share_on(job, cb))
        };
        let late = NOW + SPLIT_GRACE_SECS + 1;
        let no_split = Err(RejectReason::NoSplit);

        let (mut v, s) = build(1, true);
        assert!(v.reconstruct(&s, NOW).is_ok(), "inside the grace");
        assert_eq!(v.reconstruct(&s, late), no_split, "past the grace");
        assert_eq!(v.rebuild(&s, late), no_split, "past the grace, through rebuild");

        let (v, s) = build(0, true);
        assert!(v.reconstruct(&s, late).is_ok(), "id 0 names no coinbaser");

        let (v, s) = build(5, true);
        assert!(v.reconstruct(&s, late).is_ok(), "id 5 was never recorded");

        let (v, s) = build(1, false);
        assert!(v.reconstruct(&s, late).is_ok(), "require_split off");
    }

    #[test]
    fn the_dictated_outputs_a_coinbase_leaves_out_are_reported_with_their_identities() {
        let names = || vec!["alice".to_string(), "bob".to_string()];

        let (mut v, s) = setup();
        v.record_dictated(&split(), names(), NOW);
        let w = v.reconstruct(&s, NOW).unwrap();
        assert!(w.unpaid.is_empty());
        assert_eq!((w.paid_to_split, w.paid_to_pool), (150_000_000, COINBASE_VALUE - 150_000_000));

        let (mut v, s) = with_outputs(&split().outputs[..1]);
        v.record_dictated(&split(), names(), NOW);
        let w = v.reconstruct(&s, NOW).unwrap();
        assert_eq!(w.unpaid, vec![1]);
        assert_eq!(v.unpaid_outputs(&w), vec![("bob".to_string(), 50_000_000)]);
        assert_eq!((w.paid_to_split, w.paid_to_pool), (100_000_000, COINBASE_VALUE - 100_000_000));

        let (mut v, s) = with_outputs(&[]);
        v.record_dictated(&split(), names(), NOW);
        let w = v.reconstruct(&s, NOW).unwrap();
        assert_eq!(w.unpaid, vec![0, 1]);
        assert_eq!(
            v.unpaid_outputs(&w),
            vec![("alice".to_string(), 100_000_000), ("bob".to_string(), 50_000_000)]
        );
        assert_eq!(w.paid_to_pool, COINBASE_VALUE);

        v.record_dictated(&CoinbaserResponse { coinbaser_id: 3, ..split() }, names(), NOW);
        assert_eq!(v.unpaid_outputs(&w).len(), 2, "recorded under another id still");
        v.restore_splits(Splits::new());
        assert!(v.unpaid_outputs(&w).is_empty());

        let (mut v, s) = with_outputs(&split().outputs[..1]);
        v.record_dictated(&split(), Vec::new(), NOW);
        let w = v.reconstruct(&s, NOW).unwrap();
        assert_eq!(
            v.unpaid_outputs(&w),
            vec![(format!("script {}", hex::encode(p2wpkh(0x02))), 50_000_000)]
        );

        let (mut v, mut s) = with_outputs(&[]);
        v.record_dictated(&split(), names(), NOW);
        s.job.as_mut().unwrap().coinbaser_id = 0;
        assert!(v.reconstruct(&s, NOW).unwrap().unpaid.is_empty());

        let (mut v, s) = with_outputs(&[]);
        let fallback = CoinbaserResponse {
            value: COINBASE_VALUE - 1,
            coinbaser_id: 1,
            outputs: vec![CoinbaseOutput { value: COINBASE_VALUE - 1, script: p2wpkh(0xee) }],
        };
        v.record_dictated(&fallback, vec![String::new()], NOW);
        let w = v.reconstruct(&s, NOW).unwrap();
        assert!(w.unpaid.is_empty(), "{:?}", w.unpaid);
        assert_eq!((w.paid_to_split, w.paid_to_pool), (0, COINBASE_VALUE));
    }

    #[test]
    fn check_split_refuses_no_split_past_the_grace_and_passes_each_exemption() {
        let (mut v, s) = setup_hard();
        v.record_dictated(
            &CoinbaserResponse { value: COINBASE_VALUE, coinbaser_id: 2, outputs: vec![] },
            Vec::new(),
            NOW,
        );
        let mut w = v.reconstruct(&s, NOW).unwrap();
        assert!(!v.meets_network_target(&w));
        w.paid_to_split = 0;
        let late = NOW + SPLIT_GRACE_SECS + 1;
        let no_split = Err(RejectReason::NoSplit);

        assert_eq!(v.check_split(&s, &w, late), no_split, "past the grace");
        assert_eq!(v.check_split(&s, &w, NOW + SPLIT_GRACE_SECS), Ok(()), "at the grace");
        assert_eq!(v.check_split(&s, &w, NOW), Ok(()), "inside the grace");

        let mut off = Verifier::new(
            PoolPolicy { require_split: false, ..policy() },
            Arc::new(Mutex::new(ReplayGuard::default())),
        );
        off.record_dictated(&split(), Vec::new(), NOW);
        assert_eq!(off.check_split(&s, &w, late), Ok(()), "require_split off");

        let subsidy_only = PowSubmit { subsidy_only: true, ..s.clone() };
        assert_eq!(v.check_split(&subsidy_only, &w, late), Ok(()), "subsidy-only work");

        let paid = RebuiltShare { paid_to_split: 1, ..w.clone() };
        assert_eq!(v.check_split(&s, &paid, late), Ok(()), "a dictated output paid");

        let id0 = RebuiltShare { coinbaser_id: 0, ..w.clone() };
        assert_eq!(v.check_split(&s, &id0, late), Ok(()), "id 0 names no coinbaser");

        let id5 = RebuiltShare { coinbaser_id: 5, ..w.clone() };
        assert_eq!(v.check_split(&s, &id5, late), Ok(()), "id 5 was never recorded");

        let id2 = RebuiltShare { coinbaser_id: 2, ..w.clone() };
        assert_eq!(v.check_split(&s, &id2, late), Ok(()), "id 2 dictated nothing");

        let (v, s) = setup();
        let block = RebuiltShare { paid_to_split: 0, ..v.reconstruct(&s, NOW).unwrap() };
        assert!(v.meets_network_target(&block));
        assert_eq!(v.check_split(&s, &block, late), Ok(()), "a block");
    }

    fn setup_hard() -> (Verifier, PowSubmit) {
        let (mut v, mut s) = with_outputs(&split().outputs);
        let mut job = s.job.clone().unwrap();
        job.nbits = HARD_NBITS;
        s.job = Some(job);
        let time_on_wire = NOW as u32 + DIFF1_NTIME_OFFSET_HARD;
        s.nonce = DIFF1_NONCE_HARD;
        s.ntime = time_on_wire;
        s.blake2b = section(time_on_wire, DIFF1_NONCE_HARD);
        v.set_next_target(Some(u32::from_le_bytes(HARD_NBITS)));
        (v, s)
    }

    fn with_outputs(outputs: &[CoinbaseOutput]) -> (Verifier, PowSubmit) {
        let p = policy();
        let (cb, pot_index) = coinbase_sections(&p, outputs);
        let mut v = Verifier::new(p, Arc::new(Mutex::new(ReplayGuard::default())));
        v.record_dictated(&split(), Vec::new(), NOW);
        v.set_next_target(Some(u32::from_le_bytes(NBITS)));
        (v, share_on(job_section(pot_index), cb))
    }

    fn built_header(w: &RebuiltShare) -> HeaderV2 {
        HeaderV2::deserialize(&w.header).expect("a version 2 header")
    }

    #[test]
    fn rebuilds_a_correct_share() {
        let (mut v, s) = setup();
        let w = v.rebuild(&s, NOW).unwrap();
        assert_eq!(w.difficulty, 1);
        assert_eq!(w.height, 840_000);
        assert_eq!(w.paid_to_split, 150_000_000);
        assert_eq!(w.paid_to_pool, COINBASE_VALUE - 150_000_000);
        assert_eq!(w.header.len(), ratum::header::HEADER_V2_SIZE);
        let h = built_header(&w);
        assert_eq!(h.merkle_root, bitcoin::sha256d(&w.coinbase_tx), "no branches in this job");
        assert_eq!(h.version, 0x2000_0000);
        assert_eq!(h.prev_block, [0x5a; 32]);
        assert_eq!(h.time, s.blake2b.time_on_wire);
        assert_eq!(h.bits, u32::from_le_bytes(NBITS));
        assert_eq!(h.nonce, s.nonce);
        assert_eq!(w.block_hash, h.pow_and_block_hash().1);
        assert_eq!(
            w.coinbase_tx[s.job.as_ref().unwrap().target_byte_index as usize],
            s.target_byte
        );
        let n = s.coinbase.as_ref().unwrap().coinb1.len();
        assert_eq!(&w.coinbase_tx[n..n + share::EXTRANONCE_SIZE], &[0u8; 12]);
        assert_eq!(h.extranonce, share::header_extranonce(&EXTRANONCE).unwrap());
        let mut leaf = vec![0u8, 0, 0, 0];
        leaf.extend_from_slice(&h.precompute().h2);
        leaf.extend_from_slice(&h.extranonce);
        assert_eq!(ratum::header::blake2b_256(&leaf), h.precompute().hash1);
    }

    #[test]
    fn accepts_a_share_that_meets_the_share_target() {
        let (mut v, s) = setup();
        let a = v.verify(&s, NOW).unwrap();
        assert_eq!(a.work.difficulty, 1);
        assert!(target::meets_target(&a.work.block_hash, &target::DIFF1_TARGET));
        assert!(a.is_block);
        let mut again = s.clone();
        again.job = None;
        again.coinbase = None;
        assert_eq!(v.verify(&again, NOW), Err(RejectReason::DuplicateWork));
        let mut rolled = again.clone();
        rolled.blake2b.sia_nonce[4] = 1;
        assert_eq!(v.verify(&rolled, NOW), Err(RejectReason::HighHash));
    }

    #[test]
    fn a_share_that_misses_the_network_target_is_not_a_block() {
        let (mut v, s) = setup_hard();
        let a = v.verify(&s, NOW).unwrap();
        assert!(target::meets_target(&a.work.block_hash, &target::DIFF1_TARGET));
        assert!(!a.is_block);
    }

    #[test]
    fn the_block_flag_follows_the_mainnet_next_bits() {
        let (mut v, s) = setup_hard();
        v.set_next_target(Some(0x1a008d4f));
        let a = v.verify(&s, NOW).unwrap();
        assert!(
            !a.is_block,
            "hash {} is above the 1a008d4f target",
            hex::encode(a.work.block_hash)
        );
        let mut v2 = setup_hard().0;
        v2.set_next_target(Some(0x2100ffff));
        let b = v2.verify(&s, NOW).unwrap();
        assert!(b.is_block, "hash {} meets the easy target", hex::encode(b.work.block_hash));
    }

    #[test]
    fn an_easy_job_target_does_not_make_a_share_a_block() {
        let (mut v, s) = setup();
        v.set_next_target(Some(0x1b00_ffff));
        v.set_tip(Some([0x5a; 32]), NOW);
        v.set_tip(Some([0x11; 32]), NOW);
        let a = v.verify(&s, NOW).unwrap();
        assert!(target::meets_target(&a.work.block_hash, &target::DIFF1_TARGET));
        assert!(!a.is_block, "the job's easy bits must not make an ordinary share a block");
    }

    #[test]
    fn the_header_is_the_gateways_job_plus_the_miners_nonces() {
        let (mut v, s) = setup();
        let job = s.job.clone().unwrap();
        let w = v.rebuild(&s, NOW).unwrap();
        let h = built_header(&w);

        assert_eq!(h.prev_block, job.prev_hash);
        assert_eq!(h.height, job.height as i32);
        assert_eq!(h.bits, u32::from_le_bytes(job.nbits));
        assert_eq!(h.merkle_root, bitcoin::sha256d(&w.coinbase_tx), "no branches in this job");
        assert_eq!(h.version, 0x2000_0000);
        assert_eq!(h.xor_key, [0u8; 16]);
        assert_eq!(h.mm_rhs, [0u8; 32]);
        assert_eq!(h.xor_key_mask_clear_bits, 0);

        let b = s.blake2b;
        assert_eq!((h.nonce, h.nonce2), b.nonce_fields());
        assert_eq!((h.time_offset, h.nonce3), b.time_fields());
        assert_eq!(
            h.extranonce,
            share::header_extranonce(&s.extranonce).unwrap(),
            "the twelve sent, left-padded into the header field"
        );
        assert_eq!(h.time, b.time_on_wire, "no time offset with flags 0");
    }

    #[test]
    fn the_header_is_always_the_sia_profile() {
        let (mut v, s) = setup();
        let h = built_header(&v.rebuild(&s, NOW).unwrap());
        assert_eq!(h.asic_profile(), 0);
        assert_eq!(h.flags, 0);
        assert_eq!(h.asic_input_with(&h.precompute().hash1, &h.precompute().h2).len(), 80);
    }

    #[test]
    fn the_time_offset_flag_decides_whether_the_offset_moves_the_block_time() {
        let (v, base) = setup();
        let mut s = base.clone();
        s.blake2b.sia_ntime[..4].copy_from_slice(&600u32.to_le_bytes());
        let b = s.blake2b;
        let h = built_header(&v.reconstruct(&s, NOW).unwrap());
        assert_eq!(h.time_offset, 600);
        assert_eq!(h.time, b.time_on_wire, "flag clear: the offset is nonce space");

        s.use_time_offset = true;
        let h = built_header(&v.reconstruct(&s, NOW).unwrap());
        assert_eq!(h.time, b.time_on_wire + 600, "flag set: the offset is added to the time");
        assert_eq!(h.time_on_wire(), b.time_on_wire, "and the serialized time is unchanged");
    }

    #[test]
    fn the_header_counts_the_coinbase_among_its_transactions() {
        let (v, mut s) = setup();
        let job = s.job.clone().unwrap();
        assert_eq!(job.txn_count, 0);
        assert_eq!(built_header(&v.reconstruct(&s, NOW).unwrap()).txcount, 1, "the coinbase alone");

        let mut with_txns = job.clone();
        with_txns.txn_count = 2;
        s.job = Some(with_txns);
        assert_eq!(
            built_header(&v.reconstruct(&s, NOW).unwrap()).txcount,
            3,
            "two plus the coinbase"
        );
    }

    #[test]
    fn a_subsidy_only_header_counts_only_the_coinbase() {
        let p = policy();
        let (mut cb, pot_index) = coinbase_sections(&p, &[]);
        cb.coinbase_id = COINBASE_ID_SUBSIDY_ONLY;
        let v = Verifier::new(p, Arc::new(Mutex::new(ReplayGuard::default())));

        let mut job = job_section(pot_index);
        job.txn_count = 7;
        job.merkle_branches = vec![[0x42; 32]];

        let s = PowSubmit {
            job_id: 0,
            coinbase_id: COINBASE_ID_SUBSIDY_ONLY,
            is_block: false,
            subsidy_only: true,
            quickdiff: false,
            target_byte: 0,
            ntime: NOW as u32,
            nonce: 0,
            version: header::V2_FLAG | 0x2000_0000,
            extranonce: vec![0x33; share::EXTRANONCE_SIZE],
            username: "bc1qexample.worker1".to_string(),
            use_time_offset: false,
            job: Some(job),
            coinbase: Some(cb),
            blake2b: section(NOW as u32, 0),
            abw_slot: None,
        };
        let w = v.reconstruct(&s, NOW).expect("the job's seven transactions are not carried");
        let h = built_header(&w);
        assert_eq!(h.txcount, 1, "the coinbase alone, not the job's seven plus one");
        assert_eq!(h.merkle_root, bitcoin::sha256d(&w.coinbase_tx));
    }

    #[test]
    fn a_quickdiff_share_is_rebuilt_from_its_target_byte() {
        let (mut v, s) = setup();
        let plain = v.rebuild(&s, NOW).unwrap();
        let mut quick = s.clone();
        quick.quickdiff = true;
        let with_quickdiff = v.rebuild(&quick, NOW).unwrap();
        assert_eq!(with_quickdiff.coinbase_tx, plain.coinbase_tx);
        assert_eq!(with_quickdiff.block_hash, plain.block_hash);
    }

    #[test]
    fn shares_round_trip_through_encode_and_decode() {
        let (_, s) = setup();
        let bytes = s.encode();
        assert_eq!(bytes[17], share::EXTRANONCE_SIZE as u8);
        assert_eq!(PowSubmit::decode(&bytes).unwrap(), s);
    }

    #[test]
    fn hashes_merkle_branches_into_the_root() {
        let (v, mut s) = setup();
        let mut job = s.job.clone().unwrap();
        job.merkle_branches = vec![[0x11; 32], [0x22; 32]];
        s.job = Some(job.clone());
        let w = v.reconstruct(&s, NOW).unwrap();
        let expected =
            bitcoin::merkle_root(&bitcoin::sha256d(&w.coinbase_tx), &job.merkle_branches);
        let root = built_header(&w).merkle_root;
        assert_eq!(root, expected);
        assert_ne!(root, bitcoin::sha256d(&w.coinbase_tx));
    }

    #[test]
    fn later_shares_reuse_the_installed_sections() {
        let (mut v, first) = setup();
        let full = v.rebuild(&first, NOW).unwrap();
        let mut second = first.clone();
        second.job = None;
        second.coinbase = None;
        assert_eq!(v.rebuild(&second, NOW).unwrap(), full);
    }

    #[test]
    fn a_coinbase_section_over_the_limit_installs_nothing() {
        let (mut v, s) = setup();
        let mut big = s.clone();
        big.coinbase = Some(CoinbaseSection {
            coinbase_id: s.coinbase_id,
            coinb1: Vec::new(),
            coinb2: vec![0xcd; MAX_COINBASE_SECTION_BYTES + 1],
        });
        assert_eq!(v.rebuild(&big, NOW), Err(RejectReason::CoinbaseTooLarge));
        assert_eq!(v.installed_coinbase_bytes, 0);
        assert!(v.rebuild(&s, NOW).is_ok(), "a section at most the limit installs");
    }

    #[test]
    fn a_share_that_misses_its_target_installs_nothing() {
        let (mut v, mut s) = setup();
        v.set_next_target(Some(0x1b00_ffff));
        s.blake2b.sia_nonce[0] = s.blake2b.sia_nonce[0].wrapping_add(1);
        assert_eq!(v.rebuild(&s, NOW), Err(RejectReason::HighHash));
        assert!(v.jobs[0].is_none());
        assert_eq!(v.installed_coinbase_bytes, 0);
        let mut bad = s.clone();
        bad.coinbase.as_mut().unwrap().coinb2.push(0);
        assert_eq!(v.rebuild(&bad, NOW), Err(RejectReason::BadCoinbase));
        assert!(v.jobs[0].is_none());
    }

    #[test]
    fn a_block_that_misses_its_share_target_still_installs_its_sections() {
        let (mut v, s) = setup();
        let easy_bits = 0x207f_ffff;
        v.set_next_target(Some(easy_bits));
        let network = target::bits_to_target(easy_bits).unwrap();
        let mut block = s.clone();
        block.target_byte = 20;
        block.is_block = true;
        let pot = target::target_for_pot(block.target_byte);
        let found = (0u32..10_000).any(|nonce| {
            block.nonce = nonce;
            block.blake2b = section(block.ntime, nonce);
            let w = v.reconstruct(&block, NOW).unwrap();
            target::meets_target(&w.block_hash, &network)
                && !target::meets_target(&w.block_hash, &pot)
        });
        assert!(found);
        assert_eq!(v.rebuild(&block, NOW), Err(RejectReason::HighHash));
        assert!(v.jobs[0].is_some(), "the block's sections are installed");
        let mut bare = s.clone();
        bare.job = None;
        bare.coinbase = None;
        assert!(v.rebuild(&bare, NOW).is_ok(), "the next share on the job is served");
    }

    #[test]
    fn a_share_refused_for_its_username_or_time_still_installs_its_sections() {
        let (mut v, s) = setup();
        let mut bad = s.clone();
        bad.username = "bad name".into();
        assert_eq!(v.rebuild(&bad, NOW), Err(RejectReason::BadUsername));
        assert!(v.jobs[0].is_some());
        let mut bare = s.clone();
        bare.job = None;
        bare.coinbase = None;
        assert!(v.rebuild(&bare, NOW).is_ok(), "the next miner's share on the job is served");

        let (mut v, s) = setup();
        let late = NOW + DEFAULT_NTIME_WINDOW_SECS + 1;
        assert_eq!(v.rebuild(&s, late), Err(RejectReason::BadNtime));
        assert!(v.rebuild(&bare, NOW).is_ok());
    }

    #[test]
    fn a_first_share_refused_as_stale_still_installs_and_a_block_on_the_job_is_credited() {
        let (mut v, s) = setup_hard();
        v.set_tip(Some([0x5a; 32]), NOW);
        v.set_tip(Some([0x11; 32]), NOW);
        let late = NOW + TIP_GRACE_SECS + 1;
        assert_eq!(v.rebuild(&s, late), Err(RejectReason::StaleBlock));
        assert!(v.jobs[0].is_some(), "the stale share's sections are installed");
        v.set_next_target(Some(u32::from_le_bytes(NBITS)));
        let mut bare = s.clone();
        bare.job = None;
        bare.coinbase = None;
        assert!(v.rebuild(&bare, late).is_ok(), "a block on the stale job is still credited");
    }

    #[test]
    fn installed_coinbase_sections_are_bounded_per_connection() {
        let (mut v, s) = setup();
        v.set_next_target(Some(0x1b00_ffff));
        let per_share = coinbase_bytes(s.coinbase.as_ref().unwrap());
        v.cap = 3 * per_share;
        let on_slot = |job_id: u8| PowSubmit { job_id, ..s.clone() };
        for job_id in 0..3 {
            assert!(v.rebuild(&on_slot(job_id), NOW).is_ok());
        }
        assert_eq!(v.installed_coinbase_bytes, v.cap);
        assert_eq!(v.rebuild(&on_slot(3), NOW), Err(RejectReason::CoinbaseTooLarge));
        assert!(v.jobs[3].is_none(), "a refused share installs neither section");

        let mut replaced = on_slot(0);
        replaced.job.as_mut().unwrap().merkle_branches.push([0; 32]);
        assert_eq!(v.rebuild(&replaced, NOW), Err(RejectReason::HighHash));
        assert!(v.jobs[0].as_ref().is_some_and(|j| j.job == *s.job.as_ref().unwrap()));
        let mut bare = on_slot(0);
        bare.job = None;
        bare.coinbase = None;
        assert!(v.rebuild(&bare, NOW).is_ok(), "the installed sections still serve slot 0");
    }

    #[test]
    fn rejects_a_share_for_an_unknown_job() {
        let (mut v, s) = setup();
        let mut unknown_job = s.clone();
        unknown_job.job = None;
        unknown_job.coinbase = None;
        unknown_job.job_id = 5;
        assert_eq!(v.rebuild(&unknown_job, NOW), Err(RejectReason::BadJobId));
    }

    #[test]
    fn rejects_a_hash_above_the_share_target() {
        let (mut v, mut s) = setup();
        s.target_byte = 40;
        assert_eq!(v.verify(&s, NOW), Err(RejectReason::HighHash));
    }

    #[test]
    fn a_share_cannot_claim_more_difficulty_than_it_was_mined_at() {
        let (mut v, as_mined) = setup();
        let accepted = v.verify(&as_mined, NOW).expect("solved at difficulty 1");
        assert_eq!(accepted.work.difficulty, 1);

        let mut inflated = as_mined.clone();
        inflated.target_byte = 20;
        assert_eq!(inflated.difficulty(), 1 << 20, "what the ledger would have credited");
        assert_eq!(v.verify(&inflated, NOW), Err(RejectReason::HighHash));

        let as_mined_cb = v.reconstruct(&as_mined, NOW).unwrap().coinbase_tx;
        let inflated_cb = v.reconstruct(&inflated, NOW).unwrap().coinbase_tx;
        let differing = as_mined_cb.iter().zip(&inflated_cb).filter(|(a, b)| a != b).count();
        assert_eq!(differing, 1, "exactly the PoT byte");
    }

    #[test]
    fn a_target_byte_that_is_not_a_difficulty_exponent_is_refused() {
        let (mut v, base) = setup();
        for byte in [0xffu8, 0x80, 64] {
            let mut s = base.clone();
            s.target_byte = byte;
            assert_eq!(v.rebuild(&s, NOW), Err(RejectReason::BadTarget), "byte {byte:#04x}");
        }
    }

    #[test]
    fn rejects_difficulty_below_the_pool_minimum() {
        let mut p = policy();
        p.min_difficulty = 16384;
        let (_, s) = setup();
        let mut v = Verifier::new(p, Arc::new(Mutex::new(ReplayGuard::default())));
        v.record_dictated(&split(), Vec::new(), NOW);
        assert_eq!(v.reconstruct(&s, NOW), Err(RejectReason::BadTarget));
        let mut ok = s.clone();
        ok.target_byte = 14;
        assert!(v.reconstruct(&ok, NOW).is_ok());
    }

    #[test]
    fn rejects_a_coinbase_paying_someone_else() {
        let p = policy();
        let mut redirected = split();
        redirected.outputs[1].script = p2wpkh(0x99);
        let (cb, pot_index) = coinbase_sections(&p, &redirected.outputs);
        let mut v = Verifier::new(p, Arc::new(Mutex::new(ReplayGuard::default())));
        v.record_dictated(&split(), Vec::new(), NOW);
        let (_, base) = setup();
        let mut share = base.clone();
        share.coinbase = Some(cb);
        share.job = Some(job_section(pot_index));
        assert_eq!(v.rebuild(&share, NOW), Err(RejectReason::BadCoinbaseOutputs));
    }

    #[test]
    fn rejects_a_coinbase_whose_outputs_total_less_than_the_job_value() {
        let p = policy();
        let sp = split();
        let (mut cb, pot_index) = coinbase_sections(&p, &sp.outputs);
        let full = cb.assemble(&[0u8; share::EXTRANONCE_SIZE]);
        let remainder = bitcoin::parse_coinbase(&full).unwrap().outputs[2].value;
        let pos = cb
            .coinb2
            .windows(8)
            .position(|w| w == remainder.to_le_bytes())
            .expect("remainder output value");
        cb.coinb2[pos..pos + 8].copy_from_slice(&(remainder - 1).to_le_bytes());

        let mut v = Verifier::new(p, Arc::new(Mutex::new(ReplayGuard::default())));
        v.record_dictated(&sp, Vec::new(), NOW);
        let (_, base) = setup();
        let mut share = base.clone();
        share.coinbase = Some(cb);
        share.job = Some(job_section(pot_index));
        assert_eq!(v.rebuild(&share, NOW), Err(RejectReason::BadCoinbase));
    }

    #[test]
    fn accepts_a_split_the_gateway_could_not_fit_entirely() {
        let (v, s) = with_outputs(&split().outputs[..1]);
        let w = v.reconstruct(&s, NOW).unwrap();
        assert_eq!(w.paid_to_split, 100_000_000);
        assert_eq!(w.paid_to_pool, COINBASE_VALUE - 100_000_000);

        let (v, s) = with_outputs(&split().outputs[1..]);
        let w = v.reconstruct(&s, NOW).unwrap();
        assert_eq!(w.paid_to_split, 50_000_000);
    }

    #[test]
    fn a_repeated_coinbaser_id_cannot_outlive_the_job_naming_it() {
        assert!(MAX_JOBS > usize::from(u8::MAX));
    }

    #[test]
    fn a_share_is_checked_against_the_split_its_job_used() {
        let p = policy();
        let old_split = split();
        let (cb, pot_index) = coinbase_sections(&p, &old_split.outputs);
        let mut v = Verifier::new(p.clone(), Arc::new(Mutex::new(ReplayGuard::default())));
        v.record_dictated(&old_split, Vec::new(), NOW);
        v.record_dictated(
            &CoinbaserResponse {
                value: COINBASE_VALUE,
                coinbaser_id: old_split.coinbaser_id + 1,
                outputs: vec![CoinbaseOutput { value: COINBASE_VALUE, script: p2wpkh(0x77) }],
            },
            Vec::new(),
            NOW,
        );

        let (_, base) = setup();
        let mut share = base.clone();
        share.coinbase = Some(cb);
        let mut job = job_section(pot_index);
        job.coinbaser_id = old_split.coinbaser_id;
        share.job = Some(job);
        let w = v.rebuild(&share, NOW).unwrap();
        assert_eq!(w.paid_to_split, 150_000_000);

        let mut wrong = share.clone();
        let mut job = wrong.job.clone().unwrap();
        job.coinbaser_id = old_split.coinbaser_id + 1;
        wrong.job = Some(job);
        assert_eq!(v.rebuild(&wrong, NOW), Err(RejectReason::BadCoinbaseOutputs));
    }

    #[test]
    fn rejects_split_outputs_in_the_wrong_order() {
        let mut reordered = split().outputs;
        reordered.swap(0, 1);
        let (mut v, s) = with_outputs(&reordered);
        assert_eq!(v.rebuild(&s, NOW), Err(RejectReason::BadCoinbaseOutputs));
    }

    #[test]
    fn rejects_a_coinbase_without_the_pool_tag() {
        let mut other = policy();
        other.coinbase_tag = "SOMEONEELSE".to_string();
        let (cb, pot_index) = coinbase_sections(&other, &split().outputs);
        let mut v = verifier();
        v.record_dictated(&split(), Vec::new(), NOW);
        let (_, base) = setup();
        let mut share = base.clone();
        share.coinbase = Some(cb);
        share.job = Some(job_section(pot_index));
        assert_eq!(v.rebuild(&share, NOW), Err(RejectReason::MissingPoolTag));
    }

    fn located(p: &PoolPolicy, tagging: &Tagging) -> (usize, String) {
        let (cb, pot_index) = fixtures::coinbase(tagging, &p.payout_script, &[], COINBASE_VALUE);
        let coinbase_tx = cb.assemble(&[0u8; share::EXTRANONCE_SIZE]);
        let parsed = bitcoin::parse_coinbase(&coinbase_tx).expect("a parseable coinbase");
        let (index, tag) = locate_pot_byte(&parsed, p).expect("the pool tag is present");
        assert_eq!(index, pot_index, "the PoT byte is where the fixture placed it");
        (index, tag)
    }

    #[test]
    fn reads_the_secondary_coinbase_tag_out_of_the_tag_push() {
        let p = policy();
        let tagging =
            Tagging { tag: &p.coinbase_tag, tag_secondary: "bob", prime_id: p.prime_id as u32 };
        assert_eq!(located(&p, &tagging).1, "bob");
    }

    #[test]
    fn reads_the_secondary_tag_when_the_pool_declares_no_tag() {
        let mut p = policy();
        p.coinbase_tag = String::new();
        let tagging = Tagging { tag: "", tag_secondary: "bob", prime_id: p.prime_id as u32 };
        assert_eq!(located(&p, &tagging).1, "bob");
        let untagged = Tagging { tag: "", tag_secondary: "", prime_id: p.prime_id as u32 };
        assert_eq!(located(&p, &untagged).1, "");
    }

    #[test]
    fn a_coinbase_with_only_the_pool_tag_records_an_empty_secondary_tag() {
        let (mut v, s) = setup();
        assert_eq!(v.rebuild(&s, NOW).unwrap().tag_secondary, "");
    }

    #[test]
    fn decode_tag_removes_the_terminator_and_control_characters() {
        assert_eq!(decode_tag(b"bob\x00"), "bob");
        assert_eq!(decode_tag(b"bob"), "bob", "a push without the terminator");
        assert_eq!(decode_tag(b"a\x01b\x00"), "ab");
        assert_eq!(decode_tag(&[0xff, 0x41]), "\u{fffd}A", "invalid UTF-8 is replaced");
    }

    fn widen_prime_push(cb: &CoinbaseSection, pot_index: usize, prime_id: u64) -> CoinbaseSection {
        let mut coinb1 = cb.coinb1.clone();
        assert_eq!(coinb1[pot_index - 1], 0x07, "the 7-byte push opcode precedes the PoT byte");
        coinb1[pot_index - 1] = 0x0b;
        assert_eq!(&coinb1[pot_index + 3..pot_index + 7], &prime_id.to_le_bytes()[..4]);
        coinb1.splice(pot_index + 7..pot_index + 7, prime_id.to_le_bytes()[4..].iter().copied());
        coinb1[41] += 4;
        CoinbaseSection { coinbase_id: cb.coinbase_id, coinb1, coinb2: cb.coinb2.clone() }
    }

    #[test]
    fn accepts_the_version_3_eleven_byte_prime_push() {
        let mut wide = policy();
        wide.prime_id = 0x1122_3344_5566_7788;
        let (cb, pot_index) = coinbase_sections(&wide, &split().outputs);
        let cb = widen_prime_push(&cb, pot_index, wide.prime_id);
        let mut v = Verifier::new(wide.clone(), Arc::new(Mutex::new(ReplayGuard::default())));
        v.record_dictated(&split(), Vec::new(), NOW);
        let mut share = share_on(job_section(pot_index), cb.clone());
        share.target_byte = 5;
        let w = v.reconstruct(&share, NOW).expect("the 64-bit prime id is found in the push");
        assert_eq!(w.coinbase_tx[pot_index], 5, "the PoT byte is at the claimed index");

        let (narrow, _) = coinbase_sections(&wide, &split().outputs);
        share.coinbase = Some(narrow);
        assert_eq!(v.reconstruct(&share, NOW), Err(RejectReason::MissingPoolTag));
        let mut other = verifier();
        other.record_dictated(&split(), Vec::new(), NOW);
        share.coinbase = Some(cb);
        assert_eq!(other.reconstruct(&share, NOW), Err(RejectReason::MissingPoolTag));
    }

    #[test]
    fn a_refused_share_rebuilds_for_the_exact_reference_when_its_job_resolves() {
        let (mut v, share) = setup();
        let mut refused = share.clone();
        refused.username = String::new();
        assert_eq!(v.verify(&refused, NOW), Err(RejectReason::BadUsername));
        let work = v.rebuild_refused(&refused).expect("the job section resolves");
        assert_eq!(work.raw_hash, v.reconstruct(&share, NOW).unwrap().raw_hash);
        assert!(
            v.block_candidate(&work),
            "under the node's regtest target the refused share is a block"
        );

        let (v, share) = setup_hard();
        let mut refused = share.clone();
        refused.username = String::new();
        let work = v.rebuild_refused(&refused).expect("the job section resolves");
        assert!(!v.block_candidate(&work), "under a hard network target it is a share only");

        let mut unknown = share.clone();
        unknown.job = None;
        unknown.job_id = 9;
        assert!(v.rebuild_refused(&unknown).is_none(), "an unknown job has no work to rebuild");
    }

    #[test]
    fn a_share_on_a_revealed_slot_is_refused_but_rebuilt_for_its_reference() {
        let (mut v, share) = setup();
        let seeded = [0x11u8; 16];
        let revealed = [0x22u8; 16];
        let mut keys = AbwKeys::default();
        keys.seeded[0] = Some(seeded);
        keys.revealed[1] = Some(revealed);
        v.set_abw_keys(Some(keys));

        let mut on_seeded = share.clone();
        on_seeded.abw_slot = Some(0);
        assert_ne!(v.verify(&on_seeded, NOW), Err(RejectReason::BadAbwSlot));

        let mut on_revealed = share.clone();
        on_revealed.abw_slot = Some(1);
        assert_eq!(v.verify(&on_revealed, NOW), Err(RejectReason::BadAbwSlot));
        let work = v.rebuild_refused(&on_revealed).expect("rebuilt with the revealed key");
        assert_eq!(&work.header[112..128], &revealed, "the header carries the revealed key");

        let mut never_seeded = share.clone();
        never_seeded.abw_slot = Some(2);
        assert_eq!(v.verify(&never_seeded, NOW), Err(RejectReason::BadAbwSlot));
        assert!(v.rebuild_refused(&never_seeded).is_none());

        let mut without = share;
        without.abw_slot = None;
        assert_eq!(v.verify(&without, NOW), Err(RejectReason::BadAbwSlot));
        assert!(v.rebuild_refused(&without).is_none());
    }

    #[test]
    fn a_share_meeting_its_jobs_own_bits_is_a_block_candidate_without_being_a_block() {
        let (mut v, s) = setup();
        let job = s.job.clone().unwrap();
        v.set_next_target(Some(0x1b00_ffff));
        v.set_tip(Some(job.prev_hash), NOW);
        assert_eq!(v.verify(&s, NOW), Err(RejectReason::BadTarget));
        let work = v.rebuild_refused(&s).expect("rebuilt without the on-tip bits check");
        assert_eq!(work.job_bits, u32::from_le_bytes(NBITS));
        assert!(meets_own_bits(&work));
        assert!(v.block_candidate(&work), "a block by the job's own bits gets the receipt");

        let (mut v, s) = setup();
        v.set_next_target(Some(0x1b00_ffff));
        v.set_tip(Some([0x5a; 32]), NOW);
        v.set_tip(Some([0x11; 32]), NOW);
        let a = v.verify(&s, NOW).unwrap();
        assert!(!a.is_block, "the node's target is not met, so it is not relayed");
        assert!(v.block_candidate(&a.work), "the gateway's audit counts it as a block");

        let (mut v, s) = setup_hard();
        let a = v.verify(&s, NOW).unwrap();
        assert!(!meets_own_bits(&a.work));
        assert!(!v.block_candidate(&a.work));
    }

    #[test]
    fn rejects_a_coinbase_without_the_prime_id() {
        let mut other = policy();
        other.prime_id = 0x1234_5678;
        let (cb, pot_index) = coinbase_sections(&other, &split().outputs);
        let mut v = verifier();
        v.record_dictated(&split(), Vec::new(), NOW);
        let (_, base) = setup();
        let mut share = base.clone();
        share.coinbase = Some(cb);
        share.job = Some(job_section(pot_index));
        assert_eq!(v.rebuild(&share, NOW), Err(RejectReason::MissingPoolTag));
    }

    #[test]
    fn rejects_a_target_byte_index_pointing_elsewhere() {
        let (mut v, mut s) = setup();
        let mut job = s.job.clone().unwrap();
        job.target_byte_index += 1;
        s.job = Some(job);
        assert_eq!(v.rebuild(&s, NOW), Err(RejectReason::TargetMismatch));
    }

    #[test]
    fn rejects_an_ntime_outside_the_window() {
        let (v, s) = setup();
        let mut old = s.clone();
        old.blake2b.time_on_wire = (NOW - DEFAULT_NTIME_WINDOW_SECS - 1) as u32;
        assert_eq!(v.reconstruct(&old, NOW), Err(RejectReason::BadNtime));
        let mut ahead = s.clone();
        ahead.blake2b.time_on_wire = (NOW + DEFAULT_NTIME_WINDOW_SECS + 1) as u32;
        assert_eq!(v.reconstruct(&ahead, NOW), Err(RejectReason::BadNtime));
        let mut stale_field = s.clone();
        stale_field.ntime = (NOW - DEFAULT_NTIME_WINDOW_SECS - 1) as u32;
        assert!(v.reconstruct(&stale_field, NOW).is_ok(), "the fixed field is not the block time");
        let mut p = policy();
        p.ntime_window_secs = 0;
        let mut v = Verifier::new(p, Arc::new(Mutex::new(ReplayGuard::default())));
        v.record_dictated(&split(), Vec::new(), NOW);
        assert!(v.reconstruct(&old, NOW).is_ok());
    }

    #[test]
    fn rejects_a_bad_username() {
        let (mut v, s) = setup();
        for name in ["", "has space", "tab\there", ".", ".rig"] {
            let mut bad = s.clone();
            bad.username = name.to_string();
            assert_eq!(v.rebuild(&bad, NOW), Err(RejectReason::BadUsername), "{name:?}");
        }
    }

    #[test]
    fn a_time_offset_that_moves_the_block_time_out_of_the_window_is_refused() {
        let (v, base) = setup();
        let mut s = base.clone();
        s.blake2b.sia_ntime[..4]
            .copy_from_slice(&(DEFAULT_NTIME_WINDOW_SECS as u32 + 10).to_le_bytes());
        s.use_time_offset = true;
        assert_eq!(v.reconstruct(&s, NOW), Err(RejectReason::BadNtime));

        let mut ok = s.clone();
        ok.use_time_offset = false;
        assert!(v.reconstruct(&ok, NOW).is_ok());
    }

    #[test]
    fn rejects_a_stale_job_once_a_tip_is_known() {
        let (mut v, s) = setup_hard();
        v.set_tip(Some([0x11; 32]), NOW);
        assert_eq!(v.rebuild(&s, NOW), Err(RejectReason::StaleBlock));
        v.set_tip(Some([0x5a; 32]), NOW);
        assert!(v.rebuild(&s, NOW).is_ok());
        v.set_tip(None, NOW);
        assert!(v.rebuild(&s, NOW).is_ok());
    }

    #[test]
    fn rejects_a_tip_job_that_claims_an_easier_target_than_the_node() {
        let (mut v, s) = setup();
        v.set_tip(Some([0x5a; 32]), NOW);

        v.set_next_target(Some(0x1d00_ffff));
        assert_eq!(v.reconstruct(&s, NOW), Err(RejectReason::BadTarget));

        let mut ok = s.clone();
        let mut job = ok.job.clone().unwrap();
        job.nbits = 0x1d00_ffffu32.to_le_bytes();
        ok.job = Some(job);
        assert!(v.reconstruct(&ok, NOW).is_ok());
    }

    #[test]
    fn the_network_target_check_needs_a_tip_match_and_a_template() {
        let (mut v, s) = setup();

        v.set_next_target(Some(0x1d00_ffff));
        v.set_tip(Some([0x11; 32]), NOW);
        assert!(v.rebuild(&s, NOW).is_ok(), "a job off the tip is not target-checked");

        v.set_tip(Some([0x5a; 32]), NOW);
        v.set_next_target(None);
        assert!(v.rebuild(&s, NOW).is_ok(), "no template means no target check");
    }

    #[test]
    fn a_block_on_a_replaced_tip_is_credited_after_the_grace() {
        let (mut v, s) = setup();
        v.set_tip(Some([0x5a; 32]), NOW);
        v.set_tip(Some([0x11; 32]), NOW);
        assert!(v.rebuild(&s, NOW + 3_600).is_ok(), "the job's tip is still kept");
    }

    #[test]
    fn a_job_on_a_tip_the_pool_has_not_seen_is_kept_until_that_tip_is_replaced() {
        let (mut v, s) = setup();
        v.set_tip(Some([0x11; 32]), NOW);
        assert!(v.rebuild(&s, NOW).is_ok(), "0x5a is not a tip yet");
        v.set_tip(Some([0x22; 32]), NOW);
        v.set_tip(Some([0x33; 32]), NOW + TIP_GRACE_SECS + 1);
        assert!(v.rebuild(&s, NOW + TIP_GRACE_SECS + 1).is_ok(), "0x5a has never been a tip");
        v.set_tip(Some([0x5a; 32]), NOW + TIP_GRACE_SECS + 1);
        assert!(v.rebuild(&s, NOW + TIP_GRACE_SECS + 1).is_ok(), "0x5a is the tip");
        v.set_tip(Some([0x44; 32]), NOW + TIP_GRACE_SECS + 1);
        v.set_tip(Some([0x55; 32]), NOW + 2 * TIP_GRACE_SECS + 2);
        assert_eq!(v.rebuild(&s, NOW + 2 * TIP_GRACE_SECS + 2), Err(RejectReason::StaleBlock));
        assert!(v.jobs[0].as_ref().is_some_and(|j| j.evicted));
    }

    #[test]
    fn nothing_is_installed_into_an_evicted_slot() {
        let (mut v, s) = setup();
        v.set_tip(Some([0x5a; 32]), NOW);
        assert!(v.rebuild(&s, NOW).is_ok());
        for i in 0..=MAX_RECENT_TIPS as u8 {
            v.set_tip(Some([i; 32]), NOW);
        }
        let retained = v.installed_coinbase_bytes;
        assert!(retained > 0, "the evicted job's sections are kept for the refused rebuilds");
        let mut other = s.clone();
        other.coinbase_id = 1;
        other.coinbase.as_mut().unwrap().coinbase_id = 1;
        assert_eq!(v.rebuild(&other, NOW), Err(RejectReason::StaleBlock));
        assert_eq!(v.installed_coinbase_bytes, retained, "nothing more was installed");
    }

    #[test]
    fn a_job_is_evicted_once_its_tip_is_no_longer_kept() {
        let (mut v, s) = setup();
        v.set_tip(Some([0x5a; 32]), NOW);
        assert!(v.rebuild(&s, NOW).is_ok());
        assert!(v.installed_coinbase_bytes > 0);
        for i in 0..=MAX_RECENT_TIPS as u8 {
            v.set_tip(Some([i; 32]), NOW);
        }
        let retained = v.installed_coinbase_bytes;
        assert!(retained > 0, "the sections are kept until a share replaces the job");
        let mut bare = s.clone();
        bare.job = None;
        bare.coinbase = None;
        assert_eq!(v.rebuild(&bare, NOW), Err(RejectReason::StaleBlock));
        let work = v.rebuild_refused(&bare).expect("rebuilt from the evicted job's sections");
        assert_eq!(work.raw_hash, v.rebuild_refused(&s).unwrap().raw_hash);
        assert!(v.block_candidate(&work));
    }

    #[test]
    fn credits_the_job_the_tip_replaced_until_the_grace_ends() {
        let (mut v, s) = setup_hard();
        v.set_tip(Some([0x5a; 32]), NOW);
        v.set_tip(Some([0x11; 32]), NOW);
        assert!(v.rebuild(&s, NOW).is_ok(), "the share that replaced the tip is still credited");
        assert!(v.rebuild(&s, NOW + TIP_GRACE_SECS).is_ok(), "the grace has not ended");
        assert_eq!(
            v.rebuild(&s, NOW + TIP_GRACE_SECS + 1),
            Err(RejectReason::StaleBlock),
            "past the grace the job is stale"
        );
    }

    #[test]
    fn the_grace_outlasts_the_tips_that_follow_it() {
        let (mut v, s) = setup_hard();
        v.set_tip(Some([0x5a; 32]), NOW);
        v.set_tip(Some([0x11; 32]), NOW);
        v.set_tip(Some([0x22; 32]), NOW);
        v.set_tip(Some([0x33; 32]), NOW);
        assert!(v.rebuild(&s, NOW).is_ok(), "0x5a stopped being the tip within TIP_GRACE_SECS");
        assert_eq!(
            v.rebuild(&s, NOW + TIP_GRACE_SECS + 1),
            Err(RejectReason::StaleBlock),
            "age ends the grace, not the number of tips since"
        );
    }

    #[test]
    fn only_a_bounded_number_of_replaced_tips_is_kept() {
        let (mut v, s) = setup_hard();
        v.set_tip(Some([0x5a; 32]), NOW);
        for i in 0..=MAX_RECENT_TIPS as u8 {
            v.set_tip(Some([i; 32]), NOW);
        }
        assert_eq!(
            v.rebuild(&s, NOW),
            Err(RejectReason::StaleBlock),
            "0x5a has been removed from recent_tips"
        );
    }

    #[test]
    fn a_repeated_tip_does_not_restart_the_grace() {
        let (mut v, s) = setup_hard();
        v.set_tip(Some([0x5a; 32]), NOW);
        v.set_tip(Some([0x11; 32]), NOW);
        v.set_tip(Some([0x11; 32]), NOW + TIP_GRACE_SECS);
        assert_eq!(v.rebuild(&s, NOW + TIP_GRACE_SECS + 1), Err(RejectReason::StaleBlock));
    }

    #[test]
    fn rejects_a_coinbase_id_the_share_does_not_claim() {
        let (mut v, s) = setup();
        let mut mismatched = s.clone();
        let mut cb = mismatched.coinbase.clone().unwrap();
        cb.coinbase_id = 3;
        mismatched.coinbase = Some(cb);
        assert_eq!(v.rebuild(&mismatched, NOW), Err(RejectReason::CoinbaseIdMismatch));

        let mut out_of_range = s.clone();
        out_of_range.coinbase_id = MAX_COINBASE_TYPES;
        assert_eq!(v.rebuild(&out_of_range, NOW), Err(RejectReason::BadCoinbaseId));

        let mut wrong_subsidy = s.clone();
        wrong_subsidy.subsidy_only = true;
        assert_eq!(v.rebuild(&wrong_subsidy, NOW), Err(RejectReason::BadCoinbaseId));
    }

    #[test]
    fn rejects_a_share_for_a_coinbase_never_sent() {
        let (mut v, s) = setup();
        let mut no_cb = s.clone();
        no_cb.coinbase = None;
        assert_eq!(v.rebuild(&no_cb, NOW), Err(RejectReason::CoinbaseMissing));
    }

    #[test]
    fn a_replayed_share_is_refused_however_the_sections_are_resent() {
        let (mut v, s) = setup();
        assert!(v.verify(&s, NOW).is_ok());

        assert_eq!(v.verify(&s, NOW), Err(RejectReason::DuplicateWork));
        let mut bare = s.clone();
        bare.job = None;
        bare.coinbase = None;
        assert_eq!(v.verify(&bare, NOW), Err(RejectReason::DuplicateWork));
        let mut other = s.clone();
        let mut job = other.job.clone().unwrap();
        job.height += 1;
        other.job = Some(job);
        let _ = v.verify(&other, NOW);
        assert_eq!(v.verify(&s, NOW), Err(RejectReason::DuplicateWork));
        let mut same_work_other_job = s.clone();
        same_work_other_job.job_id = 5;
        assert_eq!(v.verify(&same_work_other_job, NOW), Err(RejectReason::DuplicateWork));
    }

    #[test]
    fn a_share_is_credited_once_across_connections() {
        let (mut first, s) = setup();
        let mut second = Verifier::new(policy(), Arc::clone(&first.replay));
        second.record_dictated(&split(), Vec::new(), NOW);

        assert!(first.verify(&s, NOW).is_ok());
        assert_eq!(second.verify(&s, NOW), Err(RejectReason::DuplicateWork));

        let mut alone = verifier();
        alone.record_dictated(&split(), Vec::new(), NOW);
        assert!(alone.verify(&s, NOW).is_ok());
    }

    #[test]
    fn replay_guard_removes_the_oldest_hash_first() {
        let mut g = ReplayGuard::new(2);
        assert!(g.accept([1; 32]));
        assert!(g.accept([2; 32]));
        assert!(!g.accept([1; 32]));
        assert_eq!(g.len(), 2);
        assert!(g.accept([3; 32]));
        assert_eq!(g.len(), 2);
        assert!(g.accept([1; 32]));
        assert!(!g.accept([3; 32]));
        let mut g = ReplayGuard::new(0);
        assert!(g.accept([9; 32]));
        assert!(!g.accept([9; 32]));
    }

    #[test]
    fn a_removed_hash_can_be_accepted_again() {
        let mut g = ReplayGuard::new(4);
        assert!(g.accept([1; 32]));
        assert!(g.accept([2; 32]));
        assert!(!g.accept([1; 32]));
        assert!(g.remove(&[1; 32]), "the hash was present");
        assert!(!g.remove(&[1; 32]), "and is gone now");
        assert_eq!(g.len(), 1);
        assert!(g.accept([1; 32]), "a removed hash is accepted again when it is resent");
        assert!(!g.accept([2; 32]), "the one that stayed is still a duplicate");
    }

    #[test]
    fn a_rejected_share_is_not_recorded_as_seen() {
        let (mut v, mut s) = setup();
        s.target_byte = 40;
        assert_eq!(v.verify(&s, NOW), Err(RejectReason::HighHash));
        assert_eq!(v.verify(&s, NOW), Err(RejectReason::HighHash));
        s.target_byte = 0;
        assert!(v.verify(&s, NOW).is_ok());
    }

    #[test]
    fn a_resent_job_section_keeps_the_coinbases_already_installed() {
        let (mut v, s) = setup();
        v.rebuild(&s, NOW).unwrap();
        let mut again = s.clone();
        again.coinbase = None;
        assert!(v.rebuild(&again, NOW).is_ok());
    }

    #[test]
    fn rebuilds_a_subsidy_only_share() {
        let p = policy();
        let (mut cb, pot_index) = coinbase_sections(&p, &[]);
        cb.coinbase_id = COINBASE_ID_SUBSIDY_ONLY;
        let v = Verifier::new(p, Arc::new(Mutex::new(ReplayGuard::default())));
        let (_, base) = setup();
        let mut share = base.clone();
        share.subsidy_only = true;
        share.coinbase_id = COINBASE_ID_SUBSIDY_ONLY;
        share.coinbase = Some(cb);
        let mut job = job_section(pot_index);
        job.merkle_branches = vec![[0x42; 32]];
        share.job = Some(job);

        let w = v.reconstruct(&share, NOW).unwrap();
        assert_eq!(w.paid_to_split, 0);
        assert_eq!(w.paid_to_pool, COINBASE_VALUE);
        assert_eq!(built_header(&w).merkle_root, bitcoin::sha256d(&w.coinbase_tx));
    }

    #[test]
    fn maps_decode_errors_to_reject_reasons() {
        assert_eq!(
            Verifier::reason_for_decode_error(&share::Error::BadExtranonceSize(16)),
            RejectReason::BadExtranonceSize
        );
        assert_eq!(
            Verifier::reason_for_decode_error(&share::Error::Truncated("x")),
            RejectReason::Other
        );
    }

    #[test]
    fn rejects_a_coinbase_that_is_not_a_transaction() {
        let (mut v, mut s) = setup();
        s.coinbase =
            Some(CoinbaseSection { coinbase_id: 0, coinb1: vec![0x01, 0x02], coinb2: vec![] });
        assert_eq!(v.rebuild(&s, NOW), Err(RejectReason::BadCoinbase));
    }

    #[test]
    fn ignores_zero_value_outputs() {
        let p = policy();
        let tx = CoinbaseTx {
            version: 1,
            script_sig_offset: 0,
            script_sig: vec![],
            sequence: 0xffff_ffff,
            outputs: vec![
                TxOut { value: 0, script: vec![0x6a, 0x0e] },
                TxOut { value: COINBASE_VALUE, script: p.payout_script.clone() },
            ],
            lock_time: 0,
            has_witness: false,
        };
        let (_, s) = setup();
        let Payments { to_split, to_pool, unpaid } =
            check_outputs(&p, &HashMap::new(), &job_section(0), &tx, &s).unwrap();
        assert_eq!((to_split, to_pool), (0, COINBASE_VALUE));
        assert!(unpaid.is_empty(), "nothing was dictated, so nothing was left out");
    }

    #[test]
    #[ignore = "searches ~2^32 hashes; run with --release -- --ignored to regenerate the nonces"]
    fn find_a_difficulty_1_nonce() {
        for (name, (mut v, mut s)) in [("DIFF1_NONCE", setup()), ("DIFF1_NONCE_HARD", setup_hard())]
        {
            let mut found = false;
            for offset in 0..16u32 {
                s.blake2b.time_on_wire = NOW as u32 + offset;
                s.ntime = s.blake2b.time_on_wire;
                let w = v.rebuild(&s, NOW + u64::from(offset)).expect("rebuild");
                let h = built_header(&w);
                let pre = h.precompute();
                let input = h.asic_input_with(&pre.hash1, &pre.h2);
                match ratum::nonce::search(
                    &input,
                    32,
                    ratum::header::blake2b_256,
                    &target::DIFF1_TARGET,
                    || false,
                ) {
                    None => println!("{name}: no solution at ntime offset {offset}"),
                    Some(nonce) => {
                        println!("{name} = {nonce:#010x}, ntime offset {offset}");
                        found = true;
                        break;
                    }
                }
            }
            assert!(found, "no nonce met difficulty 1 for {name}");
        }
    }
}
