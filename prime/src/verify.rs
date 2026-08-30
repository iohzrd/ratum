use ratum::bitcoin::{self, CoinbaseTx};
use ratum::datum::messages::{ClientConfig, CoinbaseOutput, CoinbaserResponse, RejectReason};
use ratum::datum::share::{
    self, COINBASE_ID_SUBSIDY_ONLY, CoinbaseSection, JobSection, MAX_JOBS, MAX_USERNAME, PowSubmit,
};
use ratum::header::{self, HeaderV2};
use ratum::target;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

/// `MAX_COINBASE_TYPES` in the gateway's `datum_stratum.h`, which sizes its coinbase array.
pub const MAX_COINBASE_TYPES: u8 = 6;
pub const MAX_SEEN: usize = 1 << 20;

/// The most coinbase-section bytes one connection installs. A section is installed only by a
/// share whose hash meets its share target or the network target, so each installed byte cost
/// proof of work. The C gateway and ratum-gateway rotate through at most 256 job slots, each
/// with up to 26 KB of sections (one per coinbase class), so 8 MiB is never reached.
pub const MAX_INSTALLED_COINBASE_BYTES: usize = 8 << 20;
/// The most bytes one coinbase section (`coinb1` plus `coinb2`) may hold. The C gateway's
/// `MAX_COINBASE_TXN_SIZE_BYTES` is 16 960, the extranonce 12 of them; the wire allows 128 KiB.
pub const MAX_COINBASE_SECTION_BYTES: usize = 17 << 10;

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

    /// Records a hash and reports whether it is new, removing the oldest once full.
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

    /// Removes a hash, so work that `accept` recorded but that was never credited (a share
    /// whose ledger write failed) can be credited when it is resent rather than refused as
    /// a duplicate. Returns whether it was present.
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

/// How long a job built on a replaced tip is still credited. A share meeting the
/// network target skips the staleness test, so this covers only the interval during which the
/// tip the pool holds and the tip the gateway built on differ.
pub const TIP_GRACE_SECS: u64 = 1;

/// How many replaced tips to keep. The chain can produce several tips in quick succession
/// when competing blocks arrive at the same height, and each one displaces the last, so
/// holding only the most recently replaced tip would refuse work that is still credited.
/// A job on a tip no longer kept is evicted and refused as `StaleBlock`, block or not.
const MAX_RECENT_TIPS: usize = 3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolPolicy {
    pub payout_script: Vec<u8>,
    pub prime_id: u32,
    pub coinbase_tag: String,
    pub min_difficulty: u64,
    pub ntime_window_secs: u64,
    pub activation: Option<(u32, String)>,
}

impl PoolPolicy {
    pub fn from_config(c: &ClientConfig) -> Self {
        PoolPolicy {
            payout_script: c.payout_script.clone(),
            prime_id: c.prime_id,
            coinbase_tag: c.coinbase_tag.clone(),
            min_difficulty: c.min_difficulty,
            ntime_window_secs: DEFAULT_NTIME_WINDOW_SECS,
            activation: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rebuilt {
    pub difficulty: u64,
    /// The proof-of-work hash, in the byte order targets are compared in
    /// (`HashComponents::result`).
    pub block_hash: [u8; 32],
    /// The serialized version 2 header the share names.
    pub header: [u8; header::HEADER_V2_SIZE],
    /// The assembled coinbase transaction.
    pub coinbase_tx: Vec<u8>,
    pub height: u32,
    pub txn_count: u32,
    pub paid_to_split: u64,
    pub paid_to_pool: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted {
    pub work: Rebuilt,
    pub is_block: bool,
}

#[derive(Clone, Debug)]
struct JobState {
    job: JobSection,
    coinbases: HashMap<u8, CoinbaseSection>,
    /// The parent has been the tip or a kept replaced tip. A parent the pool has not seen
    /// (the gateway's node is ahead) is never evicted.
    parent_seen: bool,
    /// The parent left the kept tips; the coinbases and merkle branches are released and
    /// shares on the parent are refused.
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
    /// One split per coinbaser id, overwritten when an id repeats. No installed job still
    /// names a repeated id: the gateway fetches at most one coinbaser per job
    /// (`datum_coinbaser.c`, only when `need_coinbaser` is set), so the `MAX_JOBS` slots are reused
    /// at least as fast as the `u8` id space is.
    splits: HashMap<u8, Vec<CoinbaseOutput>>,
    replay: Arc<Mutex<ReplayGuard>>,
    tip: Option<[u8; 32]>,
    /// The target of the block the node would build on its tip. A job building on the tip
    /// may not claim an easier target than this: a header whose bits are easier than the
    /// node's next-block nbits is rejected by the node, so shares on such a job are work that
    /// cannot become a block.
    /// `None` when no template has been read, and the check is skipped.
    tip_next_target: Option<target::Target>,
    /// Tips that are no longer current, each with the time it stopped being current.
    recent_tips: VecDeque<([u8; 32], u64)>,
    /// Bounded by `cap`.
    installed_coinbase_bytes: usize,
    /// `MAX_INSTALLED_COINBASE_BYTES`; tests lower it.
    cap: usize,
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
        }
    }

    /// Record the compact target of the block the node would build on its tip, from the
    /// `bits` a template carries. `None` bits, or bits that do not decode, leave no target
    /// and the job's network target is not checked against the chain.
    pub fn set_next_target(&mut self, next_bits: Option<u32>) {
        self.tip_next_target = next_bits.and_then(target::bits_to_target);
    }

    pub fn replay_guard(&self) -> Arc<Mutex<ReplayGuard>> {
        Arc::clone(&self.replay)
    }

    pub fn policy(&self) -> &PoolPolicy {
        &self.policy
    }

    pub fn record_split(&mut self, response: &CoinbaserResponse) {
        self.splits.insert(response.coinbaser_id, response.outputs.clone());
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
        self.tip == Some(prev_hash) || self.recent_tips.iter().any(|(h, _)| *h == prev_hash)
    }

    /// Release the jobs whose parent was a kept tip and no longer is.
    fn evict_jobs_off_recent_tips(&mut self) {
        let mut released = 0;
        for slot in self.jobs.iter_mut().flatten() {
            if slot.evicted {
                continue;
            }
            let kept = self.tip == Some(slot.job.prev_hash)
                || self.recent_tips.iter().any(|(h, _)| *h == slot.job.prev_hash);
            if kept {
                slot.parent_seen = true;
            } else if slot.parent_seen {
                released += slot.coinbase_bytes();
                slot.coinbases = HashMap::new();
                slot.job.merkle_branches = Vec::new();
                slot.evicted = true;
            }
        }
        self.installed_coinbase_bytes = self.installed_coinbase_bytes.saturating_sub(released);
    }

    /// Whether the reconstructed work meets the network target the node reports for the block
    /// it would build on its tip. This is the authoritative test for a block; the job's own
    /// `nbits` is attacker-controlled and is never trusted for it. With no template read
    /// (`tip_next_target` is `None`) nothing is a block, so nothing is relayed until the pool
    /// has the node's target.
    fn meets_network_target(&self, work: &Rebuilt) -> bool {
        self.tip_next_target
            .as_ref()
            .is_some_and(|target| target::meets_target(&work.block_hash, target))
    }

    /// Whether a job building on `prev_hash` builds on a tip that stopped being current
    /// recently enough that the work on it is still credited.
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
        // Whether the share is a block is checked against the pool's own view of the network
        // target, taken from the node's template, never against the job's self-declared
        // `nbits`: bits are attacker-controlled, and trusting them would let a gateway claim
        // arbitrarily easy bits so that every ordinary share counts as a block the pool then
        // relays and the node rejects.
        let is_block = self.meets_network_target(&work);

        if !ratum::lock(&self.replay).accept(work.block_hash) {
            return Err(RejectReason::DuplicateWork);
        }
        Ok(Accepted { work, is_block })
    }

    /// `build` and `check_share`, without installing anything.
    pub fn reconstruct(&self, s: &PowSubmit, now: u64) -> Result<Rebuilt, RejectReason> {
        let (work, prev_hash) = self.build(s)?;
        self.check_share(s, &work, prev_hash, now)?;
        Ok(work)
    }

    /// Reconstruct the share's coinbase transaction, merkle root and header from the sections
    /// it carries or the installed ones, and the pool's policy. A job on the tip claiming
    /// easier bits than the node's next block is refused as `BadTarget`. Returns the work and
    /// the job's parent.
    fn build(&self, s: &PowSubmit) -> Result<(Rebuilt, [u8; 32]), RejectReason> {
        let (job, cb) = self.resolve(s)?;
        let work = build_work(&self.policy, &self.splits, job, cb, s)?;

        // A job building on the current tip must not claim an easier network target than the
        // node's own next block. Harder bits only lower the gateway's own share rate and are not
        // checked; only shares on the tip are checked, since a job on another tip cannot be
        // compared to this template.
        if self.tip == Some(job.prev_hash)
            && let Some(node_target) = self.tip_next_target
        {
            let job_target = target::bits_to_target(u32::from_le_bytes(job.nbits))
                .ok_or(RejectReason::BadTarget)?;
            // Bigger target is easier; a job easier than the node's is refused.
            if job_target > node_target {
                return Err(RejectReason::BadTarget);
            }
        }
        Ok((work, job.prev_hash))
    }

    /// The checks that depend on the share or the moment rather than the job: staleness, the
    /// username, the time. Run after the sections are installed, so that one refused share
    /// does not leave the job without them.
    fn check_share(
        &self,
        s: &PowSubmit,
        work: &Rebuilt,
        prev_hash: [u8; 32],
        now: u64,
    ) -> Result<(), RejectReason> {
        // Whether the work is a block is determined before staleness, the order the gateway
        // uses. It submits a block to its node and forwards it here whatever the tip has since
        // become, so refusing it would discard both the block and the miner's credit. A
        // block is recognized by meeting the node's network target, never by the job's own
        // `nbits`: were `nbits` trusted here, a gateway could bypass the staleness check for
        // arbitrary off-tip work by claiming easy bits, and be credited for stale work.
        if !self.meets_network_target(work)
            && let Some(tip) = self.tip
            && prev_hash != tip
            && !self.within_tip_grace(prev_hash, now)
        {
            return Err(RejectReason::StaleBlock);
        }
        check_username_and_time(&self.policy, s, now)
    }

    /// `build`, then install the sections the share carries if its hash meets its share
    /// target or the network target, then `check_share`, then refuse a hash above the share
    /// target as `HighHash`. The gateway sends each section once whatever the verdict, so a
    /// refused share must still install them. A block is forwarded before the gateway's own
    /// difficulty check (`datum_stratum.c`, `stratum.rs`), so on a chain whose network target
    /// is easier than the miner's share target it misses its share target; it still cost the
    /// network's proof of work, and not installing it would leave every later share on the
    /// job refused as `BadJobId`.
    pub fn rebuild(&mut self, s: &PowSubmit, now: u64) -> Result<Rebuilt, RejectReason> {
        let (work, prev_hash) = self.build(s)?;
        let meets = target::meets_target(&work.block_hash, &target::target_for_pot(s.target_byte));
        if meets || self.meets_network_target(&work) {
            self.install_sections(s)?;
        }
        self.check_share(s, &work, prev_hash, now)?;
        if !meets {
            return Err(RejectReason::HighHash);
        }
        Ok(work)
    }

    /// Whether the share's job section is one the slot does not hold.
    fn brings_new_job(&self, s: &PowSubmit) -> bool {
        s.job.as_ref().is_some_and(|job| {
            self.jobs[s.job_id as usize].as_ref().is_none_or(|st| st.job != *job)
        })
    }

    /// The job and coinbase section the share is checked against: the ones it carries, else
    /// the installed ones. The gateway sends the job section while the job's
    /// `server_has_merkle_branches` is false and the coinbase section the first time each
    /// coinbase id is used for the job (`server_has_coinbase[id]`, `datum_protocol.c`).
    fn resolve<'a>(
        &'a self,
        s: &'a PowSubmit,
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

    /// Install the sections a share carries, after it met its target. A replaced job releases
    /// its bytes; a section past `MAX_INSTALLED_COINBASE_BYTES` is refused and nothing changes.
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

fn check_username_and_time(
    policy: &PoolPolicy,
    s: &PowSubmit,
    now: u64,
) -> Result<(), RejectReason> {
    if s.username.is_empty()
        || s.username.len() > MAX_USERNAME
        || !s.username.bytes().all(|b| (0x21..=0x7e).contains(&b))
        // The identity is everything before the first dot, so a leading dot leaves an empty
        // one, and the share would be credited to "".
        || s.username.starts_with('.')
    {
        return Err(RejectReason::BadUsername);
    }
    // The block time comes from the BLAKE2b section; the 32-bit `ntime` field of the upstream
    // layout is not what the header commits to. When the time-offset selector is set the
    // time the header commits to is `time_on_wire + time_offset` (`build_header_v2`, and the
    // node's `nTime = WrappingAdd(time_on_wire, offset)`), and the offset is a field the miner
    // controls, so the window has to be tested against that sum rather than the wire value it
    // could otherwise roll far past the window.
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

fn build_work(
    policy: &PoolPolicy,
    splits: &HashMap<u8, Vec<CoinbaseOutput>>,
    job: &JobSection,
    cb: &CoinbaseSection,
    s: &PowSubmit,
) -> Result<Rebuilt, RejectReason> {
    if s.target_byte >= 64
        || u64::from(s.target_byte) < u64::from(target::floor_pot(policy.min_difficulty))
    {
        return Err(RejectReason::BadTarget);
    }
    // The header carries the extranonce, so the coinbase holds twelve zero bytes where the
    // upstream format splices it in. The `quickdiff` flag is informational: the work's
    // uniqueness is the target byte written in below (upstream overwrote coinb1 for it).
    let mut coinbase_tx = cb.assemble(&[0u8; share::EXTRANONCE_SIZE]);

    let parsed = bitcoin::parse_coinbase(&coinbase_tx).map_err(|_| RejectReason::BadCoinbase)?;
    if parsed.has_witness {
        return Err(RejectReason::BadCoinbase);
    }

    let pot_index = locate_pot_byte(&parsed, policy, job.height)?;
    if usize::from(s.target_byte_index_of(job)) != pot_index {
        return Err(RejectReason::TargetMismatch);
    }
    coinbase_tx[pot_index] = s.target_byte;

    let (paid_to_split, paid_to_pool) = check_outputs(policy, splits, job, &parsed, s)?;

    // A subsidy-only block holds nothing but the coinbase, so its merkle root is the
    // coinbase hash and there is no branch to hash in.
    let branches: &[[u8; 32]] = if s.subsidy_only { &[] } else { job.merkle_branches.as_slice() };
    let merkle_root = bitcoin::merkle_root(&bitcoin::sha256d(&coinbase_tx), branches);

    let h = build_header_v2(job, s, &s.blake2b, &merkle_root)?;

    Ok(Rebuilt {
        difficulty: s.difficulty(),
        block_hash: h.hash_components().result,
        header: h.serialize(),
        coinbase_tx,
        height: job.height,
        txn_count: job.txn_count,
        paid_to_split,
        paid_to_pool,
    })
}

/// The header the hardware hashed, built from the job section the gateway sent (kept by
/// `install_sections`), the pool's policy, and the fields the hardware controls.
///
/// The pool constructs rather than verifies. Every field the hardware does not set comes
/// from the kept job section or from pool policy, so the share carries nothing to cross-check
/// them against; only the fields the miner sets come from the share.
fn build_header_v2(
    job: &JobSection,
    s: &PowSubmit,
    b: &share::Blake2bSection,
    merkle_root: &[u8; 32],
) -> Result<HeaderV2, RejectReason> {
    let (nonce, nonce2) = b.nonce_fields();
    let (time_offset, nonce3) = b.time_fields();
    // The share carries the twelve bytes that vary; the header field's leading four are
    // the ones the gateway holds at zero.
    let extranonce =
        share::header_extranonce(&s.extranonce).ok_or(RejectReason::BadExtranonceSize)?;
    // The header counts the coinbase among the block's transactions and the job counts
    // only what follows it, so a block the node accepts needs one more than the job declares
    // (`validation.cpp`: for a version 2 header, `block.m_txcount != block.vtx.size()`).
    // Subsidy-only work carries the coinbase alone.
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
        // Profile 0, the Sia layout, is the only one the DATUM share format can carry and the
        // only one the gateway issues; the share carries no profile field. The
        // time-offset selector is carried in the message's reserved bytes.
        flags: if s.use_time_offset { header::FLAG_USE_TIME_OFFSET } else { 0 },
        // Set by pool policy; the gateway does not supply it. A null key makes the mask zero, so
        // the miner receives true block hashes; when an anti-withholding key is configured it is
        // filled in here and the gateway never receives it.
        xor_key_mask_clear_bits: 0,
        xor_key: [0u8; 16],
        height: job.height as i32,
        mm_rhs: [0u8; 32],
    };
    if s.use_time_offset {
        h.time = b.time_on_wire.wrapping_add(time_offset);
    }
    Ok(h)
}

fn locate_pot_byte(
    tx: &CoinbaseTx,
    policy: &PoolPolicy,
    height: u32,
) -> Result<usize, RejectReason> {
    let pushes = bitcoin::script_pushes(&tx.script_sig);
    let prime = policy.prime_id.to_le_bytes();
    let uid_push = pushes
        .iter()
        .position(|(_, data)| data.len() == 7 && data[3..7] == prime)
        .ok_or(RejectReason::MissingPoolTag)?;

    match &policy.activation {
        Some((activation_height, headline)) if *activation_height == height => {
            let wanted = headline.as_bytes();
            let found =
                !wanted.is_empty() && tx.script_sig.windows(wanted.len()).any(|w| w == wanted);
            if !found {
                return Err(RejectReason::MissingHeadline);
            }
        }
        _ => {
            if !policy.coinbase_tag.is_empty() {
                let tag = policy.coinbase_tag.as_bytes();
                let ok = uid_push > 0 && {
                    let (_, data) = pushes[uid_push - 1];
                    data.len() > tag.len()
                        && &data[..tag.len()] == tag
                        // What the gateway writes after the primary tag: 0x00 when it
                        // is the only tag, 0x0F when a secondary one follows.
                        && matches!(data[tag.len()], 0x00 | 0x0f)
                };
                if !ok {
                    return Err(RejectReason::MissingPoolTag);
                }
            }
        }
    }

    Ok(tx.script_sig_offset + pushes[uid_push].0)
}

fn check_outputs(
    policy: &PoolPolicy,
    splits: &HashMap<u8, Vec<CoinbaseOutput>>,
    job: &JobSection,
    tx: &CoinbaseTx,
    s: &PowSubmit,
) -> Result<(u64, u64), RejectReason> {
    let empty: Vec<CoinbaseOutput> = Vec::new();
    let dictated =
        if s.subsidy_only { &empty } else { splits.get(&job.coinbaser_id).unwrap_or(&empty) };

    // `next` only increases, so the dictated outputs must appear in the order the
    // pool sent them, though outputs paying the pool may appear between them.
    let mut next = 0usize;
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

    Ok((paid_to_split, paid_to_pool))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratum::bitcoin::TxOut;

    /// The gateway builds a share's sections from the header the miner produced
    /// (`Blake2bSection::from_header`, `share_extranonce`); the pool rebuilds the header from
    /// them here. The two must be inverses.
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
        };
        assert_eq!(build_header_v2(&job, &s, &b, &h.merkle_root).unwrap(), h);
    }

    const NOW: u64 = 1_760_000_000;
    const NBITS: [u8; 4] = [0xff, 0xff, 0x7f, 0x20];
    const COINBASE_VALUE: u64 = 312_500_000;

    const EXTRANONCE: [u8; share::EXTRANONCE_SIZE] = [0x33; share::EXTRANONCE_SIZE];
    const HARD_NBITS: [u8; 4] = [0xff, 0xff, 0x00, 0x1c];
    /// Nonces meeting difficulty 1 for the header `setup` and `setup_hard` build, found by
    /// `find_a_difficulty_1_nonce` (ignored: it searches the nonce space). The job's bits are
    /// hashed, so the two jobs need different nonces.
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
            activation: None,
        }
    }

    use ratum::fixtures::{self, Tagging, p2wpkh};

    fn coinbase_sections(p: &PoolPolicy, outputs: &[CoinbaseOutput]) -> (CoinbaseSection, usize) {
        let tagging = Tagging { tag: &p.coinbase_tag, prime_id: p.prime_id, headline: None };
        fixtures::coinbase(&tagging, &p.payout_script, outputs, COINBASE_VALUE)
    }

    fn activation_coinbase(
        p: &PoolPolicy,
        headline: &str,
        outputs: &[CoinbaseOutput],
    ) -> (CoinbaseSection, usize) {
        let tagging = Tagging { tag: "", prime_id: p.prime_id, headline: Some(headline) };
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

    /// The section a profile-0 share carries for `nonce` at `time_on_wire`: `m_nonce2`,
    /// `m_nonce3` and the time offset zero.
    fn section(time_on_wire: u32, nonce: u32) -> share::Blake2bSection {
        let mut sia_nonce = [0u8; 8];
        sia_nonce[..4].copy_from_slice(&nonce.to_le_bytes());
        share::Blake2bSection { sia_ntime: [0u8; 8], sia_nonce, time_on_wire }
    }

    /// A share on `job` and `cb` whose header meets difficulty 1 when the job's bits are
    /// `NBITS` and the section is the one `setup` gives it.
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
        }
    }

    fn setup() -> (Verifier, PowSubmit) {
        with_outputs(&split().outputs)
    }

    /// `setup` with the job's bits at a target no share here meets, and the node's next block
    /// at the same target, so a share meeting difficulty 1 is a share and not a block: whether
    /// a share is a block is determined by the node's template, not the job's bits.
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
        let mut v = Verifier::new(p);
        v.record_split(&split());
        // The normal case: the node's next-block target equals the job's bits, so a share
        // meeting that target is a block. Tests that exercise the on-tip check override this.
        v.set_next_target(Some(u32::from_le_bytes(NBITS)));
        (v, share_on(job_section(pot_index), cb))
    }

    /// The header the pool built for a share, deserialized from the header it would relay.
    fn built_header(w: &Rebuilt) -> HeaderV2 {
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
        assert_eq!(w.block_hash, h.hash_components().result);
        assert_eq!(
            w.coinbase_tx[s.job.as_ref().unwrap().target_byte_index as usize],
            s.target_byte
        );
        // The header carries the extranonce; the coinbase holds zeros in its place.
        let n = s.coinbase.as_ref().unwrap().coinb1.len();
        assert_eq!(&w.coinbase_tx[n..n + share::EXTRANONCE_SIZE], &[0u8; 12]);
        assert_eq!(h.extranonce, share::header_extranonce(&EXTRANONCE).unwrap());
        // The Stratum leaf: coinb1 (three zero bytes and h2) with the extranonce after it,
        // under the 0x00 prefix the Siacoin hasher adds.
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
        rolled.blake2b.sia_nonce[4] = 1; // m_nonce2, the second half of the Sia nonce
        assert_eq!(v.verify(&rolled, NOW), Err(RejectReason::HighHash));
    }

    #[test]
    fn a_share_that_misses_the_network_target_is_not_a_block() {
        let (mut v, s) = setup_hard();
        let a = v.verify(&s, NOW).unwrap();
        assert!(target::meets_target(&a.work.block_hash, &target::DIFF1_TARGET));
        assert!(!a.is_block);
    }

    /// Whether a share is a block comes from the node's template target, not the job's own bits.
    /// A share whose job claims an arbitrarily easy target cannot make the pool treat it as a
    /// block (and relay a block the node rejects) when the node's next block is at a target the
    /// share does not meet.
    #[test]
    fn an_easy_job_target_does_not_make_a_share_a_block() {
        let (mut v, s) = setup(); // the job's own nbits are the easiest target
        // The node's next-block target is harder than the diff-1 target this share meets.
        v.set_next_target(Some(0x1b00_ffff));
        // The job builds on 0x5a, which was the tip before the last change, so the share is
        // within TIP_GRACE_SECS and not stale, and being off the current tip the easier-than-node
        // check does not apply. Whether it is a block is left to the node's target alone.
        v.set_tip(Some([0x5a; 32]), NOW);
        v.set_tip(Some([0x11; 32]), NOW);
        let a = v.verify(&s, NOW).unwrap();
        assert!(target::meets_target(&a.work.block_hash, &target::DIFF1_TARGET));
        assert!(!a.is_block, "the job's easy bits must not make an ordinary share a block");
    }

    /// The pool fills every header field the miner does not control from the job section the
    /// gateway sent: the merkle root, prev_block, height, bits, version and txcount. The share
    /// supplies only the nonce fields and the time-offset selector.
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
        // Pool policy, and null while the anti-withholding key is unused.
        assert_eq!(h.xor_key, [0u8; 16]);
        assert_eq!(h.mm_rhs, [0u8; 32]);
        assert_eq!(h.xor_key_mask_clear_bits, 0);

        // The Sia fields split into four header fields, in this order.
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

    /// Profile 0 is the only layout the DATUM share format can carry, so it is the only one the
    /// pool can build. Nothing in a share can select another.
    #[test]
    fn the_header_is_always_the_sia_profile() {
        let (mut v, s) = setup();
        let h = built_header(&v.rebuild(&s, NOW).unwrap());
        assert_eq!(h.asic_profile(), 0);
        assert_eq!(h.flags, 0);
        assert_eq!(h.asic_input_with(&h.precompute().hash1, &h.precompute().h2).len(), 80);
    }

    /// The time-offset selector adds the offset to the block time; without it the offset is
    /// only nonce.
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

    /// The header counts the coinbase; the job counts only what follows it. With the wrong
    /// count the node rejects the block (`block.m_txcount != block.vtx.size()`).
    /// The pool fills it in from the job, so there is no count to disagree with.
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

    /// Subsidy-only work carries the coinbase and nothing else, however many transactions
    /// the job declares after it, so its header counts one rather than one more than the job.
    #[test]
    fn a_subsidy_only_header_counts_only_the_coinbase() {
        let p = policy();
        // No dictated split: subsidy-only work may pay nobody but the pool.
        let (mut cb, pot_index) = coinbase_sections(&p, &[]);
        cb.coinbase_id = COINBASE_ID_SUBSIDY_ONLY;
        let v = Verifier::new(p);

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
        };
        let w = v.reconstruct(&s, NOW).expect("the job's seven transactions are not carried");
        let h = built_header(&w);
        assert_eq!(h.txcount, 1, "the coinbase alone, not the job's seven plus one");
        // No branches are hashed in either, so the root is the coinbase hash itself.
        assert_eq!(h.merkle_root, bitcoin::sha256d(&w.coinbase_tx));
    }

    #[test]
    fn a_quickdiff_share_is_rebuilt_from_its_target_byte() {
        // The gateway makes quickdiff work unique through the PoT byte, which reaches here
        // as target_byte and is written into the coinbase whether or not the flag is set
        // (the upstream SHA256d format overwrote coinb1 instead), so the rebuild is
        // identical either way.
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
        // A network target the rolled hash does not meet, so only the share target counts.
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

    /// The gateway forwards a block before its own difficulty check, with the share target
    /// byte of the stratum job. When the network target is easier than that share target the
    /// block misses its share target; it is refused as `HighHash` but its sections are
    /// installed, so later shares on the job are served.
    #[test]
    fn a_block_that_misses_its_share_target_still_installs_its_sections() {
        let (mut v, s) = setup();
        // A network target a random hash meets with probability 1/2.
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
        // The node's next block is now at the share's target, so the same work is a block.
        v.set_next_target(Some(u32::from_le_bytes(NBITS)));
        let mut bare = s.clone();
        bare.job = None;
        bare.coinbase = None;
        assert!(v.rebuild(&bare, late).is_ok(), "a block on the stale job is still credited");
    }

    #[test]
    fn installed_coinbase_sections_are_bounded_per_connection() {
        // The same job and coinbase in every slot: each share meets its target and each slot
        // installs its own copy of the section.
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

        // A share that would replace the job but misses its target changes nothing.
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

    /// What the PoT byte is for. It is written into the coinbase before the
    /// pool hashes, so a share cannot be submitted as work done at a difficulty other than
    /// the one it was mined at: the rebuilt coinbase differs, and with it the merkle root
    /// and the hash. Without it a gateway's claim would be accepted as declared, and the
    /// ledger credits `1 << target_byte`: the share below is credited 1, and the same work
    /// claiming twenty bits more would be credited 1048576.
    #[test]
    fn a_share_cannot_claim_more_difficulty_than_it_was_mined_at() {
        let (mut v, as_mined) = setup();
        let accepted = v.verify(&as_mined, NOW).expect("solved at difficulty 1");
        assert_eq!(accepted.work.difficulty, 1);

        let mut inflated = as_mined.clone();
        inflated.target_byte = 20;
        assert_eq!(inflated.difficulty(), 1 << 20, "what the ledger would have credited");
        assert_eq!(v.verify(&inflated, NOW), Err(RejectReason::HighHash));

        // The claim is committed, so the pool rebuilds a different coinbase for it: one
        // byte different, which is the whole mechanism.
        let as_mined_cb = v.reconstruct(&as_mined, NOW).unwrap().coinbase_tx;
        let inflated_cb = v.reconstruct(&inflated, NOW).unwrap().coinbase_tx;
        let differing = as_mined_cb.iter().zip(&inflated_cb).filter(|(a, b)| a != b).count();
        assert_eq!(differing, 1, "exactly the PoT byte");
    }

    /// A share whose target byte is not a difficulty exponent: what a gateway that never wrote
    /// the PoT byte into the coinbase sends, since the byte it reads back is whatever was
    /// already there. It is refused rather than credited as 2^63.
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
        let mut v = Verifier::new(p);
        v.record_split(&split());
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
        let mut v = Verifier::new(p);
        v.record_split(&split());
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

        let mut v = Verifier::new(p);
        v.record_split(&sp);
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
        // `splits` keeps one entry per id and drops the previous. Shrinking the job slots
        // below the id space would let a job outlive the split it names, and its shares
        // would then be checked against a different one.
        assert!(MAX_JOBS > usize::from(u8::MAX));
    }

    #[test]
    fn a_share_is_checked_against_the_split_its_job_used() {
        let p = policy();
        let old_split = split();
        let (cb, pot_index) = coinbase_sections(&p, &old_split.outputs);
        let mut v = Verifier::new(p.clone());
        v.record_split(&old_split);
        v.record_split(&CoinbaserResponse {
            value: COINBASE_VALUE,
            coinbaser_id: old_split.coinbaser_id + 1,
            outputs: vec![CoinbaseOutput { value: COINBASE_VALUE, script: p2wpkh(0x77) }],
        });

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
        let mut v = Verifier::new(policy());
        v.record_split(&split());
        let (_, base) = setup();
        let mut share = base.clone();
        share.coinbase = Some(cb);
        share.job = Some(job_section(pot_index));
        assert_eq!(v.rebuild(&share, NOW), Err(RejectReason::MissingPoolTag));
    }

    #[test]
    fn rejects_a_coinbase_without_the_prime_id() {
        let mut other = policy();
        other.prime_id = 0x1234_5678;
        let (cb, pot_index) = coinbase_sections(&other, &split().outputs);
        let mut v = Verifier::new(policy());
        v.record_split(&split());
        let (_, base) = setup();
        let mut share = base.clone();
        share.coinbase = Some(cb);
        share.job = Some(job_section(pot_index));
        assert_eq!(v.rebuild(&share, NOW), Err(RejectReason::MissingPoolTag));
    }

    const HEADLINE: &str = "RATUM 2026 the fork that let the SC-Lite mine bitcoin";

    #[test]
    fn accepts_the_activation_block_whose_coinbase_carries_the_headline() {
        let mut p = policy();
        p.activation = Some((840_000, HEADLINE.to_string()));
        let (cb, pot_index) = activation_coinbase(&p, HEADLINE, &split().outputs);
        let mut v = Verifier::new(p);
        v.record_split(&split());
        let (_, base) = setup();
        let mut share = base.clone();
        share.coinbase = Some(cb);
        share.job = Some(job_section(pot_index));
        let w = v.reconstruct(&share, NOW).unwrap();
        assert_eq!(w.height, 840_000);
        assert_eq!(w.paid_to_split, 150_000_000);
    }

    #[test]
    fn rejects_an_activation_block_without_the_headline() {
        let mut p = policy();
        p.activation = Some((840_000, HEADLINE.to_string()));
        let (cb, pot_index) = activation_coinbase(&p, "SOME OTHER HEADLINE", &split().outputs);
        let mut v = Verifier::new(p);
        v.record_split(&split());
        let (_, base) = setup();
        let mut share = base.clone();
        share.coinbase = Some(cb);
        share.job = Some(job_section(pot_index));
        assert_eq!(v.rebuild(&share, NOW), Err(RejectReason::MissingHeadline));
    }

    #[test]
    fn the_headline_rule_applies_only_at_the_activation_height() {
        let mut p = policy();
        p.activation = Some((840_001, HEADLINE.to_string()));
        let (cb, pot_index) = activation_coinbase(&p, HEADLINE, &split().outputs);
        let mut v = Verifier::new(p);
        v.record_split(&split());
        let (_, base) = setup();
        let mut share = base.clone();
        share.coinbase = Some(cb);
        share.job = Some(job_section(pot_index));
        assert_eq!(v.rebuild(&share, NOW), Err(RejectReason::MissingPoolTag));

        let mut p = policy();
        p.activation = Some((840_001, HEADLINE.to_string()));
        let (cb, pot_index) = coinbase_sections(&p, &split().outputs);
        let mut v = Verifier::new(p);
        v.record_split(&split());
        let mut share = base.clone();
        share.coinbase = Some(cb);
        share.job = Some(job_section(pot_index));
        assert!(v.rebuild(&share, NOW).is_ok());
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
        // The block time is the section's `time_on_wire`; the fixed `ntime` field is not
        // what the header commits to, and is left as it is.
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
        let mut v = Verifier::new(p);
        v.record_split(&split());
        assert!(v.reconstruct(&old, NOW).is_ok());
    }

    #[test]
    fn rejects_a_bad_username() {
        let (mut v, s) = setup();
        // A leading dot leaves the identity (everything before the first dot) empty, which
        // must be refused rather than credited to "".
        for name in ["", "has space", "tab\there", ".", ".rig"] {
            let mut bad = s.clone();
            bad.username = name.to_string();
            assert_eq!(v.rebuild(&bad, NOW), Err(RejectReason::BadUsername), "{name:?}");
        }
    }

    #[test]
    fn a_time_offset_that_moves_the_block_time_out_of_the_window_is_refused() {
        let (v, base) = setup();
        // The serialized time is current, but a large offset with the selector set puts the
        // block time the node commits to (serialized + offset) past the
        // window.
        let mut s = base.clone();
        s.blake2b.sia_ntime[..4]
            .copy_from_slice(&(DEFAULT_NTIME_WINDOW_SECS as u32 + 10).to_le_bytes());
        s.use_time_offset = true;
        assert_eq!(v.reconstruct(&s, NOW), Err(RejectReason::BadNtime));

        // The same offset with the selector clear is only nonce space, so the block time is
        // still the serialized time and stays inside the window.
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
        // The setup job builds on 0x5a... at regtest bits (0x207fffff), the easiest target.
        let (mut v, s) = setup();
        v.set_tip(Some([0x5a; 32]), NOW);

        // The node's next block is harder (bits 0x1d00ffff), so the job's easier bits are refused.
        v.set_next_target(Some(0x1d00_ffff));
        assert_eq!(v.reconstruct(&s, NOW), Err(RejectReason::BadTarget));

        // A job at least as hard as the node's next block is accepted.
        let mut ok = s.clone();
        let mut job = ok.job.clone().unwrap();
        job.nbits = 0x1d00_ffffu32.to_le_bytes();
        ok.job = Some(job);
        assert!(v.reconstruct(&ok, NOW).is_ok());
    }

    #[test]
    fn the_network_target_check_needs_a_tip_match_and_a_template() {
        let (mut v, s) = setup();

        // A harder template is set, but the job builds on 0x5a... while the tip is elsewhere,
        // so the two are not comparable and the job is not refused for its bits.
        v.set_next_target(Some(0x1d00_ffff));
        v.set_tip(Some([0x11; 32]), NOW);
        assert!(v.rebuild(&s, NOW).is_ok(), "a job off the tip is not target-checked");

        // On the tip but with no template read, the check is skipped.
        v.set_tip(Some([0x5a; 32]), NOW);
        v.set_next_target(None);
        assert!(v.rebuild(&s, NOW).is_ok(), "no template means no target check");
    }

    #[test]
    fn a_block_on_a_replaced_tip_is_credited_after_the_grace() {
        // The gateway tests for a block before it tests for staleness and forwards the
        // block either way, so the tip it replaced must not refuse the finder's block.
        let (mut v, s) = setup();
        v.set_tip(Some([0x5a; 32]), NOW);
        v.set_tip(Some([0x11; 32]), NOW);
        assert!(v.rebuild(&s, NOW + 3_600).is_ok(), "the job's tip is still kept");
    }

    #[test]
    fn a_job_on_a_tip_the_pool_has_not_seen_is_kept_until_that_tip_is_replaced() {
        // The gateway's node is ahead of the pool's: the job's parent is a block the pool has
        // not polled yet, or a competitor the pool's node reorgs to later.
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
        let mut other = s.clone();
        other.coinbase_id = 1;
        other.coinbase.as_mut().unwrap().coinbase_id = 1;
        assert_eq!(v.rebuild(&other, NOW), Err(RejectReason::StaleBlock));
        assert_eq!(v.installed_coinbase_bytes, 0);
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
        assert_eq!(v.installed_coinbase_bytes, 0, "the job's coinbases were released");
        let mut bare = s.clone();
        bare.job = None;
        bare.coinbase = None;
        assert_eq!(v.rebuild(&bare, NOW), Err(RejectReason::StaleBlock));
    }

    #[test]
    fn credits_the_job_the_tip_replaced_until_the_grace_ends() {
        let (mut v, s) = setup_hard();
        // The share's job builds on 0x5a. The tip is replaced, which is what a share that
        // is itself a block does: the gateway submits the block, the pool's node reports it,
        // and only then does the share arrive.
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
        // Competing blocks at one height replace each other in quick succession. The job's
        // parent is still recent, and work on it could still become the tip.
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
        // The watcher reports the same tip again later; it is not a change, so the grace
        // still runs from when the tip changed.
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
        let mut second = Verifier::with_replay_guard(policy(), first.replay_guard());
        second.record_split(&split());

        assert!(first.verify(&s, NOW).is_ok());
        assert_eq!(second.verify(&s, NOW), Err(RejectReason::DuplicateWork));

        let mut alone = Verifier::new(policy());
        alone.record_split(&split());
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
        let v = Verifier::new(p);
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
        let paid = check_outputs(&p, &HashMap::new(), &job_section(0), &tx, &s).unwrap();
        assert_eq!(paid, (0, COINBASE_VALUE));
    }

    /// Regenerates `DIFF1_NONCE` and `DIFF1_NONCE_HARD` with their ntime offsets: search
    /// against the header the pool would build, at the section's `time_on_wire` stepped from
    /// `NOW`.
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
