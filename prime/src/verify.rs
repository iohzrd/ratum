use ratum::bitcoin::{self, CoinbaseTx};
use ratum::datum::coinbase::{
    TAG_END, TAG_SEPARATOR, UID_PUSH_PREFIX_SIZE, UID_PUSH_SIZE_V1, UID_PUSH_SIZE_V3,
};
use ratum::datum::messages::{ClientConfig, CoinbaseOutput, CoinbaserResponse, RejectReason};
use ratum::datum::share::{
    self, COINBASE_ID_SUBSIDY_ONLY, CoinbaseSection, JobSection, MAX_COINBASE_SECTION_BYTES,
    MAX_JOBS, MAX_USERNAME, PowSubmit,
};
use ratum::header::{self, HeaderV2};
use ratum::target;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

pub const MAX_COINBASE_TYPES: u8 = 6;
pub const MAX_SEEN: usize = 1 << 20;

pub const MAX_INSTALLED_COINBASE_BYTES: usize = 16 << 20;

#[derive(Debug)]
pub struct ReplayGuard {
    seen: HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
    capacity: usize,
}

impl ReplayGuard {
    pub fn new(capacity: usize) -> Self {
        ReplayGuard { seen: HashSet::new(), order: VecDeque::new(), capacity: capacity.max(1) }
    }

    pub fn accept(&mut self, hash: [u8; 32]) -> bool {
        if !self.seen.insert(hash) {
            return false;
        }
        self.order.push_back(hash);
        while self.order.len() > self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        true
    }

    pub fn remove(&mut self, hash: &[u8; 32]) -> bool {
        if !self.seen.remove(hash) {
            return false;
        }
        if let Some(pos) = self.order.iter().position(|h| h == hash) {
            self.order.remove(pos);
        }
        true
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

impl Default for ReplayGuard {
    fn default() -> Self {
        ReplayGuard::new(MAX_SEEN)
    }
}

pub const DEFAULT_NTIME_WINDOW_SECS: u64 = 2 * 60 * 60;

pub const TIP_GRACE_SECS: u64 = 1;

pub const SPLIT_GRACE_SECS: u64 = 10;

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
        PoolPolicy {
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
    pub seeded: [Option<[u8; 16]>; 16],
    pub revealed: [Option<[u8; 16]>; 16],
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

#[derive(Clone, Debug)]
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
    pub fn new(policy: PoolPolicy) -> Self {
        Verifier::with_replay_guard(policy, Arc::new(Mutex::new(ReplayGuard::default())))
    }

    pub fn with_replay_guard(policy: PoolPolicy, replay: Arc<Mutex<ReplayGuard>>) -> Self {
        Verifier {
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

    pub fn replay_guard(&self) -> Arc<Mutex<ReplayGuard>> {
        Arc::clone(&self.replay)
    }

    pub fn policy(&self) -> &PoolPolicy {
        &self.policy
    }

    pub fn record_split(&mut self, response: &CoinbaserResponse, now: u64) {
        self.record_dictated(response, Vec::new(), now);
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
        let Verifier { jobs, tip, recent_tips, .. } = self;
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

    pub fn reconstruct(&self, s: &PowSubmit, now: u64) -> Result<Rebuilt, RejectReason> {
        let (work, prev_hash) = self.build(s)?;
        self.check_share(s, &work, prev_hash, now)?;
        Ok(work)
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
        let work = build_work(&self.policy, &self.splits, job, cb, s, abw_key)?;
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

    pub fn rebuild(&mut self, s: &PowSubmit, now: u64) -> Result<Rebuilt, RejectReason> {
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

pub fn meets_own_bits(work: &Rebuilt) -> bool {
    target::bits_to_target(work.job_bits)
        .is_some_and(|t| target::meets_target(&work.block_hash, &t))
}

fn build_work(
    policy: &PoolPolicy,
    splits: &Splits,
    job: &JobSection,
    cb: &CoinbaseSection,
    s: &PowSubmit,
    abw_key: Option<[u8; 16]>,
) -> Result<Rebuilt, RejectReason> {
    if s.target_byte > target::MAX_TARGET_POT
        || u64::from(s.target_byte) < u64::from(target::floor_pot(policy.min_difficulty))
    {
        return Err(RejectReason::BadTarget);
    }
    let mut coinbase_tx = cb.assemble(&[0u8; share::EXTRANONCE_SIZE]);

    let parsed = bitcoin::parse_coinbase(&coinbase_tx).map_err(|_| RejectReason::BadCoinbase)?;
    if parsed.has_witness {
        return Err(RejectReason::BadCoinbase);
    }

    let (pot_index, tag_secondary) = locate_pot_byte(&parsed, policy)?;
    if usize::from(s.target_byte_index_of(job)) != pot_index {
        return Err(RejectReason::TargetMismatch);
    }
    coinbase_tx[pot_index] = s.target_byte;

    let Payments { to_split: paid_to_split, to_pool: paid_to_pool, unpaid } =
        check_outputs(policy, splits, job, &parsed, s)?;

    let branches: &[[u8; 32]] = if s.subsidy_only { &[] } else { job.merkle_branches.as_slice() };
    let merkle_root = bitcoin::merkle_root(&bitcoin::sha256d(&coinbase_tx), branches);

    let h = build_header_v2(job, s, &s.blake2b, &merkle_root, abw_key)?;

    let hc = h.hash_components();
    Ok(Rebuilt {
        difficulty: s.difficulty(),
        block_hash: hc.result,
        raw_hash: hc.hash2,
        job_bits: u32::from_le_bytes(job.nbits),
        header: h.serialize(),
        coinbase_tx,
        height: job.height,
        txn_count: job.txn_count,
        coinbaser_id: job.coinbaser_id,
        paid_to_split,
        paid_to_pool,
        unpaid,
        tag_secondary,
    })
}

fn build_header_v2(
    job: &JobSection,
    s: &PowSubmit,
    b: &share::Blake2bSection,
    merkle_root: &[u8; 32],
    abw_key: Option<[u8; 16]>,
) -> Result<HeaderV2, RejectReason> {
    let (nonce, nonce2) = b.nonce_fields();
    let (time_offset, nonce3) = b.time_fields();
    let extranonce =
        share::header_extranonce(&s.extranonce).ok_or(RejectReason::BadExtranonceSize)?;
    let tx_count = if s.subsidy_only { 1 } else { u64::from(job.txn_count) + 1 };
    let txcount = u16::try_from(tx_count).map_err(|_| RejectReason::BadCoinbase)?;

    let mut h = HeaderV2 {
        version: (s.version & !header::V2_FLAG) as i32,
        prev_block: job.prev_hash,
        merkle_root: *merkle_root,
        time: b.time_on_wire,
        bits: u32::from_le_bytes(job.nbits),
        nonce,
        nonce2,
        nonce3,
        extranonce,
        time_offset,
        txcount,
        flags: if s.use_time_offset { header::FLAG_USE_TIME_OFFSET } else { 0 },
        xor_key_mask_clear_bits: abw_key
            .map_or(0, |_| ratum::datum::abw::clear_bits(s.target_byte)),
        xor_key: abw_key.unwrap_or([0u8; 16]),
        height: job.height as i32,
        mm_rhs: [0u8; 32],
    };
    if s.use_time_offset {
        h.time = b.time_on_wire.wrapping_add(time_offset);
    }
    Ok(h)
}

fn locate_pot_byte(tx: &CoinbaseTx, policy: &PoolPolicy) -> Result<(usize, String), RejectReason> {
    let pushes = bitcoin::script_pushes(&tx.script_sig);
    let prime = policy.prime_id.to_le_bytes();
    let uid_push = pushes
        .iter()
        .position(|(_, data)| {
            let Some(id) = data.get(UID_PUSH_PREFIX_SIZE..) else { return false };
            match data.len() {
                UID_PUSH_SIZE_V1 => {
                    policy.prime_id <= u64::from(u32::MAX) && id == &prime[..size_of::<u32>()]
                }
                UID_PUSH_SIZE_V3 => id == prime,
                _ => false,
            }
        })
        .ok_or(RejectReason::MissingPoolTag)?;

    let mut tag_secondary = String::new();
    let tag_push = uid_push.checked_sub(1).map(|i| pushes[i].1);
    if !policy.coinbase_tag.is_empty() {
        let tag = policy.coinbase_tag.as_bytes();
        let after_tag = tag_push
            .filter(|data| data.len() > tag.len() && &data[..tag.len()] == tag)
            .map(|data| (data, data[tag.len()]))
            .filter(|(_, marker)| matches!(*marker, TAG_END | TAG_SEPARATOR))
            .ok_or(RejectReason::MissingPoolTag)?;
        if after_tag.1 == TAG_SEPARATOR {
            tag_secondary = decode_tag(&after_tag.0[tag.len() + 1..]);
        }
    } else if let Some(data) = tag_push
        && data.first() == Some(&TAG_SEPARATOR)
    {
        tag_secondary = decode_tag(&data[1..]);
    }

    Ok((tx.script_sig_offset + pushes[uid_push].0, tag_secondary))
}

fn decode_tag(bytes: &[u8]) -> String {
    let bytes = bytes.strip_suffix(&[TAG_END]).unwrap_or(bytes);
    String::from_utf8_lossy(bytes).chars().filter(|c| !c.is_control()).collect()
}

struct Payments {
    to_split: u64,
    to_pool: u64,
    unpaid: Vec<usize>,
}

fn check_outputs(
    policy: &PoolPolicy,
    splits: &Splits,
    job: &JobSection,
    tx: &CoinbaseTx,
    s: &PowSubmit,
) -> Result<Payments, RejectReason> {
    let recorded = if s.subsidy_only { None } else { splits.get(&job.coinbaser_id) };
    let empty: Vec<CoinbaseOutput> = Vec::new();
    let dictated = recorded.map_or(&empty, |d| &d.outputs);

    let mut next = 0usize;
    let mut paid = vec![false; dictated.len()];
    let mut paid_to_split = 0u64;
    let mut paid_to_pool = 0u64;
    for out in &tx.outputs {
        if out.value == 0 {
            continue;
        }
        if let Some(pos) =
            dictated[next..].iter().position(|d| d.value == out.value && d.script == out.script)
        {
            paid_to_split = paid_to_split.saturating_add(out.value);
            paid[next + pos] = true;
            next += pos + 1;
            continue;
        }
        if out.script == policy.payout_script {
            paid_to_pool = paid_to_pool.saturating_add(out.value);
            continue;
        }
        return Err(RejectReason::BadCoinbaseOutputs);
    }

    if !s.subsidy_only && paid_to_split.saturating_add(paid_to_pool) != job.coinbase_value {
        return Err(RejectReason::BadCoinbase);
    }

    let unpaid = dictated
        .iter()
        .enumerate()
        .filter(|(i, d)| !paid[*i] && d.script != policy.payout_script)
        .map(|(i, _)| i)
        .collect();

    Ok(Payments { to_split: paid_to_split, to_pool: paid_to_pool, unpaid })
}
