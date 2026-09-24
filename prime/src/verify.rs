//! Verifying a share against one connection's jobs, splits and tip. The share is rebuilt first, so
//! a refusal can still carry the exact hash the gateway computed, and the reasons that outrank a
//! later failure are decided before it.

mod jobs;
mod rebuild;
#[cfg(test)]
mod tests;

use crate::abw::{AbwSlotState, SlotKeyStatus};
use crate::ledger::split::Payout;
use crate::payout::DictatedOutput;
use ratum::datum::messages;
use ratum::datum::messages::config::ClientConfig;
use ratum::datum::messages::share::{
    MAX_COINBASE_SECTION_LEN, MAX_JOBS, MAX_USERNAME_LEN, PowSubmit,
};
use ratum::datum::messages::share_response::RejectReason;
use ratum::header;
use ratum::{rpc, target};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

pub use jobs::{BlockCheck, JobTxns};

/// The coinbase sections one connection's jobs may hold: twice what a gateway installs when
/// every job slot carries one coinbase at `MAX_COINBASE_SECTION_LEN`. A slot may hold more,
/// since `check_coinbase_id` admits `MAX_COINBASE_TYPES` ids and the subsidy-only one, so this
/// cap rather than that count is what bounds the bytes: past it a share carrying a further
/// coinbase is rejected. It bounds one gateway, so the pool's total is this times
/// `--max-connections`.
const MAX_INSTALLED_COINBASE_BYTES: usize = 2 * MAX_JOBS * MAX_COINBASE_SECTION_LEN;

pub const NTIME_WINDOW_SECS: u64 = 2 * ratum::SECS_PER_HOUR;

const SPLIT_GRACE_SECS: u64 = 10;

/// The splits one session keeps. A gateway requests one per job, so this covers the jobs of
/// several tips; past it the oldest is dropped, and a share naming it is checked as naming no
/// split.
const MAX_SPLITS: usize = 64;

/// The splits a saved session keeps. A resumed gateway replays the shares queued at its
/// disconnect, on the jobs live then, one split each, so a few cover them; more would hold
/// memory for the hour the session is kept, which any client can fill by requesting splits.
pub const SAVED_SPLITS: usize = 8;

/// The version bits a miner may roll (BIP 320). A share whose version differs from the version
/// its job's block was validated with outside these bits is refused, since the node checks the
/// rest of the version (the minimum version and any signalling a deployment requires).
pub const VERSION_ROLLING_MASK: u32 = 0x1fff_e000;

/// What a share is checked against: the configuration sent to every gateway (its version 1
/// form; a version 3 session adds the version 3 fields) and the pool's own share rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharePolicy {
    pub config: ClientConfig,
    /// The chain the node reported at startup, none when it did not answer, whose address
    /// prefixes a miner's identity carries (`payout::address_script`).
    pub chain: Option<rpc::Chain>,
}

/// A refused share: the reason, and the share as rebuilt when its job, coinbase and slot key
/// resolved, for its exact reference (the receipt and the response's hash).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub reason: RejectReason,
    pub rebuilt: Option<Box<RebuiltShare>>,
}

impl Refusal {
    fn unreferenced(reason: RejectReason) -> Self {
        Self { reason, rebuilt: None }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RebuiltShare {
    /// The block hash meets the node's next target as the verifier held it at the rebuild.
    /// Whether the share is relayed is decided by its job's own bits once the node has
    /// validated the job (`meets_own_bits`).
    pub is_block: bool,
    pub difficulty: u64,
    pub block_hash: [u8; 32],
    pub raw_pow_hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub job_bits: u32,
    pub header: [u8; header::HEADER_V2_SIZE],
    pub coinbase_tx: Vec<u8>,
    pub height: u32,
    pub txn_count: u32,
    pub coinbaser_id: u8,
    pub paid_to_split: u64,
    pub paid_to_pool: u64,
    /// The dictated outputs the coinbase left out, other than those paying the pool's script.
    pub unpaid_outputs: Vec<Payout>,
    pub tag_secondary: String,
    /// The header version without the version 2 flag, which `VERSION_ROLLING_MASK` compares.
    pub version: u32,
    /// SHA-256d of the coinbase section the share was rebuilt on (`coinb1 || coinb2`) and of
    /// whether the share is subsidy-only, which keys the node's verdict on the job's block with
    /// that coinbase. A subsidy-only share's block holds the coinbase alone and a pooled
    /// share's the job's transactions too, so the same coinbase bytes make two blocks, and the
    /// verdict on one is not the verdict on the other.
    pub coinbase_digest: [u8; 32],
    /// The generation of the job installed in the share's slot when the share was rebuilt on
    /// it; none when the share's job was not installed (a share refused before its sections
    /// were installed, or on a job another share has since replaced).
    pub job_generation: Option<u64>,
}

impl RebuiltShare {
    /// A block by the node's next target or by its job's own bits: the measure of the
    /// gateway's reveal audit, so the share gets a receipt whether or not it is relayed.
    pub fn is_block_candidate(&self) -> bool {
        self.is_block || meets_own_bits(self)
    }

    /// A block by its job's own bits: what the pool relays once the node has validated the
    /// job, whose bits are then the ones the node requires of it.
    pub fn meets_own_bits(&self) -> bool {
        meets_own_bits(self)
    }
}

/// A split the pool dictated: its outputs, and the value and previous block hash of the
/// coinbaser request it answered, which a job naming it must match (`check_outputs`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DictatedSplit {
    pub outputs: Arc<[DictatedOutput]>,
    pub value: u64,
    pub prev_hash: [u8; 32],
    pub sent_at: u64,
}

/// The splits a session dictated, by coinbaser id, and the id of the newest; saved with a
/// version 3 session so the shares a resumed gateway replays are checked against them. At
/// most `MAX_SPLITS` are held, and consecutive splits with the same outputs share them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DictatedSplits {
    last_id: u8,
    by_id: HashMap<u8, DictatedSplit>,
    order: VecDeque<u8>,
}

impl DictatedSplits {
    /// The id the next split takes: the one after the newest, skipping 0, which names no
    /// coinbaser.
    pub fn next_id(&self) -> u8 {
        match self.last_id.wrapping_add(1) {
            0 => 1,
            next => next,
        }
    }

    pub fn record(
        &mut self,
        id: u8,
        value: u64,
        prev_hash: [u8; 32],
        outputs: Vec<DictatedOutput>,
        sent_at: u64,
    ) {
        let outputs: Arc<[DictatedOutput]> = match self.by_id.get(&self.last_id) {
            Some(last) if *last.outputs == *outputs => Arc::clone(&last.outputs),
            _ => outputs.into(),
        };
        self.order.retain(|held| *held != id);
        self.by_id.insert(id, DictatedSplit { outputs, value, prev_hash, sent_at });
        self.order.push_back(id);
        self.last_id = id;
        self.keep_newest(MAX_SPLITS);
    }

    /// Drops the oldest splits until at most `n` remain.
    fn keep_newest(&mut self, n: usize) {
        while self.order.len() > n {
            if let Some(oldest) = self.order.pop_front() {
                self.by_id.remove(&oldest);
            }
        }
    }

    pub fn get(&self, id: u8) -> Option<&DictatedSplit> {
        self.by_id.get(&id)
    }

    /// Drops the splits dictated for a previous block hash `keep` refuses: a share on a job
    /// whose parent is no longer credited cannot use them.
    pub fn retain_prev(&mut self, keep: impl Fn(&[u8; 32]) -> bool) {
        self.by_id.retain(|_, split| keep(&split.prev_hash));
        let by_id = &self.by_id;
        self.order.retain(|id| by_id.contains_key(id));
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.by_id.len()
    }
}

/// What the node's template says of the block it describes, as far as the verifier holds it:
/// its bits, and, when read from the node rather than set by a test, its parent, height and
/// earliest valid block time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NextBlock {
    prev_hash: Option<[u8; 32]>,
    bits: u32,
    height: Option<u32>,
    mintime: Option<u64>,
}

/// How many bits easier than the template's target a job on another parent may name for its
/// block to be submitted (`Verifier::relayable`): 2, the fourfold easing one retarget allows.
const MAX_RELAY_TARGET_SHIFT: u32 = 2;

/// Whether the chain lets a block carry the minimum difficulty when its time is far enough past
/// its parent's (testnet and testnet4). There the bits a block requires depend on its own
/// time, so a job's bits are checked by the node's validation of the job, not against the
/// template's.
fn allows_min_difficulty_blocks(chain: Option<rpc::Chain>) -> bool {
    matches!(chain, Some(rpc::Chain::Test | rpc::Chain::Testnet4))
}

/// The share checks of one connection. The policy is the server's, borrowed: it is fixed at
/// startup and every connection checks against the same one.
#[derive(Debug)]
pub struct Verifier<'a> {
    policy: &'a SharePolicy,
    jobs: Vec<Option<jobs::JobState>>,
    splits: DictatedSplits,
    tip: Option<[u8; 32]>,
    next: Option<NextBlock>,
    recent_tips: VecDeque<jobs::ReplacedTip>,
    /// The generation the next job installed takes, so a job replaced in its slot is told
    /// apart from the job replacing it.
    next_generation: u64,
    /// The pow hashes of the shares that installed sections on this connection: one share
    /// installs sections once, so a single share resent under other job and coinbase ids
    /// cannot fill the section cap.
    installed_by: crate::bounded::BoundedSet<[u8; 32]>,
    installed_coinbase_bytes: usize,
    /// `MAX_INSTALLED_COINBASE_BYTES` for the life of every connection. It is a field rather
    /// than the constant so a test can lower it and reach the cap without installing tens of
    /// megabytes of sections; nothing in the pool varies it.
    installed_coinbase_bytes_cap: usize,
}

impl<'a> Verifier<'a> {
    pub fn new(policy: &'a SharePolicy) -> Self {
        Self {
            policy,
            jobs: vec![None; MAX_JOBS],
            splits: DictatedSplits::default(),
            tip: None,
            next: None,
            recent_tips: VecDeque::new(),
            next_generation: 1,
            installed_by: crate::bounded::BoundedSet::new(jobs::MAX_INSTALLING_SHARES),
            installed_coinbase_bytes: 0,
            installed_coinbase_bytes_cap: MAX_INSTALLED_COINBASE_BYTES,
        }
    }

    pub fn tip(&self) -> Option<[u8; 32]> {
        self.tip
    }

    /// Sets the node's template for the next block; returns whether its bits changed.
    pub fn set_template(&mut self, template: Option<rpc::TemplateSummary>) -> bool {
        let next = template.map(|t| NextBlock {
            prev_hash: Some(t.prev_hash),
            bits: t.bits,
            height: Some(t.height),
            mintime: Some(t.mintime),
        });
        let changed = self.next.map(|n| n.bits) != next.map(|n| n.bits);
        self.next = next;
        changed
    }

    /// Sets the bits of the node's next block alone, as a template read without its other
    /// fields; returns whether they changed.
    #[cfg(test)]
    pub fn set_next_bits(&mut self, next_bits: Option<u32>) -> bool {
        let next =
            next_bits.map(|bits| NextBlock { prev_hash: None, bits, height: None, mintime: None });
        std::mem::replace(&mut self.next, next).map(|n| n.bits) != next_bits
    }

    fn next_target(&self) -> Option<target::Target> {
        self.next.and_then(|n| target::bits_to_target(n.bits))
    }

    /// Whether a refused share that meets its job's own bits is submitted to the node, which
    /// then decides it. The bits are the gateway's, and `check_job_header` compares them with
    /// the template's only for a job on the template's parent, so on another parent they could
    /// name any target and make every share a block to submit. There the job's target may be
    /// at most `MAX_RELAY_TARGET_SHIFT` bits easier than the template's: one retarget eases a
    /// target at most fourfold, which covers a job on the tip the template replaced. On
    /// testnet and testnet4, whose blocks may carry the minimum difficulty, and while the pool
    /// holds no template, the bits are not compared.
    pub fn relayable(&self, rebuilt: &RebuiltShare) -> bool {
        if !rebuilt.meets_own_bits() {
            return false;
        }
        if allows_min_difficulty_blocks(self.policy.chain) {
            return true;
        }
        if let Some(next) = self.next_on(rebuilt.prev_hash) {
            return rebuilt.job_bits == next.bits;
        }
        match (self.next_target(), target::bits_to_target(rebuilt.job_bits)) {
            (Some(next), Some(own)) => own <= target::shl_saturating(&next, MAX_RELAY_TARGET_SHIFT),
            _ => true,
        }
    }

    /// The template, when it describes the block a job on `prev_hash` builds: its parent is
    /// the template's, or, for a template set without one, the tip's.
    fn next_on(&self, prev_hash: [u8; 32]) -> Option<NextBlock> {
        self.next.filter(|n| match n.prev_hash {
            Some(parent) => parent == prev_hash,
            None => self.tip == Some(prev_hash),
        })
    }

    pub fn next_coinbaser_id(&self) -> u8 {
        self.splits.next_id()
    }

    pub fn record_dictated(
        &mut self,
        coinbaser_id: u8,
        value: u64,
        prev_hash: [u8; 32],
        outputs: Vec<DictatedOutput>,
        now: u64,
    ) {
        self.splits.record(coinbaser_id, value, prev_hash, outputs, now);
    }

    /// The splits to save with a session: the newest `SAVED_SPLITS` of those dictated on the
    /// tip or on a tip replaced recently enough that a share on it can still be credited.
    pub fn take_splits(&mut self) -> DictatedSplits {
        let mut splits = std::mem::take(&mut self.splits);
        if self.tip.is_some() {
            splits.retain_prev(|prev| self.tip == Some(*prev) || self.recent_tip(*prev));
        }
        splits.keep_newest(SAVED_SPLITS);
        splits
    }

    pub fn restore_splits(&mut self, splits: DictatedSplits) {
        self.splits = splits;
    }

    pub fn reason_for_decode_error(e: &messages::Error) -> RejectReason {
        match e {
            messages::Error::BadExtranonceSize(_) => RejectReason::BadExtranonceSize,
            messages::Error::BadUsername => RejectReason::BadUsername,
            messages::Error::BadMerkleCount(_) => RejectReason::BadMerkleCount,
            messages::Error::BadBlake2bSection | messages::Error::MissingBlake2bSection => {
                RejectReason::BadBlake2bSection
            }
            _ => RejectReason::Other,
        }
    }

    /// Rebuilds the share. A share naming an evicted job (`StaleBlock`) or a revealed slot
    /// key (`BadAbwSlot`) is still rebuilt and refused with the rebuilt share; that reason is
    /// checked first, so it replaces the reason of any failure after it.
    fn rebuild(&self, s: &PowSubmit, abw: Option<&AbwSlotState>) -> Result<RebuiltShare, Refusal> {
        Self::check_coinbase_id(s).map_err(Refusal::unreferenced)?;
        let stale = self.names_evicted_job(s).then_some(RejectReason::StaleBlock);
        let refuse =
            |first: Option<RejectReason>, reason| Refusal::unreferenced(first.unwrap_or(reason));
        let (job, cb) = self.resolve(s).map_err(|reason| refuse(stale, reason))?;
        let slot_key = abw
            .map(|abw| {
                s.abw_slot
                    .and_then(|slot| abw.key_for(slot))
                    .ok_or_else(|| refuse(stale, RejectReason::BadAbwSlot))
            })
            .transpose()?;
        let revealed = slot_key.is_some_and(|(_, status)| status == SlotKeyStatus::Revealed);
        let first = stale.or(revealed.then_some(RejectReason::BadAbwSlot));
        let rebuilt = self
            .rebuild_share(job, cb, s, slot_key.map(|(key, _)| key))
            .map_err(|reason| refuse(first, reason))?;
        match first {
            Some(reason) => Err(Refusal { reason, rebuilt: Some(Box::new(rebuilt)) }),
            None => Ok(rebuilt),
        }
    }

    /// The header fields of a job on the template's parent that the template decides: the
    /// bits (except where the chain lets a block's own time lower them), the height, and the
    /// earliest block time. The node's validation of the job checks the same fields; these
    /// refuse a share before that, and the time is checked per share since each share
    /// carries its own.
    fn check_job_header(&self, s: &PowSubmit, rebuilt: &RebuiltShare) -> Result<(), RejectReason> {
        let Some(next) = self.next_on(rebuilt.prev_hash) else { return Ok(()) };
        if !allows_min_difficulty_blocks(self.policy.chain) && rebuilt.job_bits != next.bits {
            return Err(RejectReason::BadTarget);
        }
        if next.height.is_some_and(|height| height != rebuilt.height) {
            return Err(RejectReason::HeaderFieldMismatch);
        }
        if next.mintime.is_some_and(|mintime| u64::from(s.block_time()) < mintime) {
            return Err(RejectReason::BadNtime);
        }
        Ok(())
    }

    /// A share on a previous block other than the tip is stale, unless the tip was replaced
    /// within the grace, or the share is a block on a parent the node has reported (relayed,
    /// so the node decides it). A share on a parent the node has not reported is stale here
    /// whether or not it is a block, and the connection holds it for the node to report the
    /// parent (`parent_unseen`).
    fn check_share(
        &self,
        s: &PowSubmit,
        rebuilt: &RebuiltShare,
        now: u64,
    ) -> Result<(), RejectReason> {
        if let Some(tip) = self.tip
            && rebuilt.prev_hash != tip
            && !self.within_tip_grace(rebuilt.prev_hash, now)
            && (!rebuilt.is_block || self.parent_unseen(s, rebuilt.prev_hash))
        {
            return Err(RejectReason::StaleBlock);
        }
        self.check_split(s, rebuilt, now)?;
        check_username_and_time(s, now)
    }

    fn check_split(
        &self,
        s: &PowSubmit,
        rebuilt: &RebuiltShare,
        now: u64,
    ) -> Result<(), RejectReason> {
        if s.subsidy_only
            || rebuilt.paid_to_split != 0
            || rebuilt.coinbaser_id == 0
            || rebuilt.is_block
        {
            return Ok(());
        }
        match self.splits.get(rebuilt.coinbaser_id) {
            Some(split)
                if !split.outputs.is_empty()
                    && now.saturating_sub(split.sent_at) > SPLIT_GRACE_SECS =>
            {
                Err(RejectReason::NoSplit)
            }
            _ => Ok(()),
        }
    }

    /// `verify` as if the share's hash met its own target, so a test need not search for a
    /// nonce. Every other check, and their order, is the one `verify` applies.
    #[cfg(test)]
    fn rebuild_checked_ignoring_target(
        &mut self,
        s: &PowSubmit,
        abw: Option<&AbwSlotState>,
        now: u64,
    ) -> Result<RebuiltShare, RejectReason> {
        let rebuilt = self.rebuild(s, abw).map_err(|refusal| refusal.reason)?;
        self.check_rebuilt(s, &rebuilt, now, true)?;
        Ok(rebuilt)
    }

    /// Rebuilds the share and checks it against this connection's jobs, splits and tip. A
    /// share accepted here may still repeat one accepted before: `accounting::claim` decides
    /// that across every connection.
    pub fn verify(
        &mut self,
        s: &PowSubmit,
        abw: Option<&AbwSlotState>,
        now: u64,
    ) -> Result<RebuiltShare, Refusal> {
        let rebuilt = self.rebuild(s, abw).map_err(|mut refusal| {
            if let Some(r) = &mut refusal.rebuilt {
                r.job_generation = self.installed_generation(s);
            }
            refusal
        })?;
        let meets_share_target = meets_share_target(s, &rebuilt);
        let checked = self.check_rebuilt(s, &rebuilt, now, meets_share_target);
        let rebuilt = RebuiltShare { job_generation: self.installed_generation(s), ..rebuilt };
        match checked {
            Ok(()) => Ok(rebuilt),
            Err(reason) => Err(Refusal { reason, rebuilt: Some(Box::new(rebuilt)) }),
        }
    }

    /// The checks a rebuilt share passes, in the order a later failure must not replace an
    /// earlier reason: the job's target, then the sections it installs, then the share.
    fn check_rebuilt(
        &mut self,
        s: &PowSubmit,
        rebuilt: &RebuiltShare,
        now: u64,
        meets_share_target: bool,
    ) -> Result<(), RejectReason> {
        self.check_job_header(s, rebuilt)?;
        if meets_share_target || rebuilt.is_block {
            self.install_sections(s, rebuilt.raw_pow_hash, now)?;
        }
        self.check_share(s, rebuilt, now)?;
        if !meets_share_target {
            return Err(RejectReason::HighHash);
        }
        Ok(())
    }
}

const PRINTABLE_ASCII: std::ops::RangeInclusive<u8> = 0x21..=0x7e;

fn check_username_and_time(s: &PowSubmit, now: u64) -> Result<(), RejectReason> {
    if s.username.is_empty()
        || s.username.len() > MAX_USERNAME_LEN
        || !s.username.bytes().all(|b| PRINTABLE_ASCII.contains(&b))
        || s.username.starts_with('.')
    {
        return Err(RejectReason::BadUsername);
    }
    if u64::from(s.block_time()).abs_diff(now) > NTIME_WINDOW_SECS {
        return Err(RejectReason::BadNtime);
    }
    Ok(())
}

/// Whether the share's hash meets the target its target byte names.
pub fn meets_share_target(s: &PowSubmit, rebuilt: &RebuiltShare) -> bool {
    target::meets_target(&rebuilt.raw_pow_hash, &target::target_for_exponent(s.target_byte))
}

fn meets_own_bits(rebuilt: &RebuiltShare) -> bool {
    target::bits_to_target(rebuilt.job_bits)
        .is_some_and(|t| target::meets_target(&rebuilt.block_hash, &t))
}
