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
use ratum::datum::messages::share::{MAX_JOBS, MAX_USERNAME_LEN, PowSubmit};
use ratum::datum::messages::share_response::RejectReason;
use ratum::header;
use ratum::{rpc, target};
use std::collections::{HashMap, VecDeque};

/// The coinbase sections one connection's jobs may hold, about twice what a gateway serving
/// every job slot with the widest split the coinbaser dictates (512 outputs) installs. It
/// bounds one gateway, so the pool's total is this times `--max-connections`.
const MAX_INSTALLED_COINBASE_BYTES: usize = 16 << 20;

pub const NTIME_WINDOW_SECS: u64 = 2 * ratum::SECS_PER_HOUR;

const SPLIT_GRACE_SECS: u64 = 10;

/// What a share is checked against: the configuration sent to every gateway (its version 1
/// form; a version 3 session adds the version 3 fields) and the pool's own share rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharePolicy {
    pub config: ClientConfig,
    pub require_split: bool,
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
    /// The block hash meets the node's next target as the verifier held it at the rebuild:
    /// the share is a block and is relayed.
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
}

impl RebuiltShare {
    /// A block by the node's next target or by its job's own bits: the measure of the
    /// gateway's reveal audit, so the share gets a receipt whether or not it is relayed.
    pub fn is_block_candidate(&self) -> bool {
        self.is_block || meets_own_bits(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DictatedSplit {
    pub outputs: Vec<DictatedOutput>,
    pub sent_at: u64,
}

/// The splits a session dictated, by coinbaser id, and the id of the newest; saved with a
/// version 3 session so the shares a resumed gateway replays are checked against them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DictatedSplits {
    last_id: u8,
    by_id: HashMap<u8, DictatedSplit>,
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

    pub fn record(&mut self, id: u8, outputs: Vec<DictatedOutput>, sent_at: u64) {
        self.by_id.insert(id, DictatedSplit { outputs, sent_at });
        self.last_id = id;
    }

    pub fn get(&self, id: u8) -> Option<&DictatedSplit> {
        self.by_id.get(&id)
    }
}

/// The share checks of one connection. The policy is the server's, borrowed: it is fixed at
/// startup and every connection checks against the same one.
#[derive(Debug)]
pub struct Verifier<'a> {
    policy: &'a SharePolicy,
    jobs: Vec<Option<jobs::JobState>>,
    splits: DictatedSplits,
    tip: Option<[u8; 32]>,
    next_bits: Option<u32>,
    recent_tips: VecDeque<jobs::ReplacedTip>,
    installed_coinbase_bytes: usize,
    /// `MAX_INSTALLED_COINBASE_BYTES` for the life of every connection. It is a field rather
    /// than the constant so a test can lower it and reach the cap without installing sixteen
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
            next_bits: None,
            recent_tips: VecDeque::new(),
            installed_coinbase_bytes: 0,
            installed_coinbase_bytes_cap: MAX_INSTALLED_COINBASE_BYTES,
        }
    }

    pub fn tip(&self) -> Option<[u8; 32]> {
        self.tip
    }

    /// Sets the bits of the node's next block template; returns whether they changed.
    pub fn set_next_bits(&mut self, next_bits: Option<u32>) -> bool {
        std::mem::replace(&mut self.next_bits, next_bits) != next_bits
    }

    fn next_target(&self) -> Option<target::Target> {
        self.next_bits.and_then(target::bits_to_target)
    }

    pub fn next_coinbaser_id(&self) -> u8 {
        self.splits.next_id()
    }

    pub fn record_dictated(&mut self, coinbaser_id: u8, outputs: Vec<DictatedOutput>, now: u64) {
        self.splits.record(coinbaser_id, outputs, now);
    }

    pub fn take_splits(&mut self) -> DictatedSplits {
        std::mem::take(&mut self.splits)
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

    fn check_job_target(&self, rebuilt: &RebuiltShare) -> Result<(), RejectReason> {
        if self.tip == Some(rebuilt.prev_hash)
            && let Some(node_target) = self.next_target()
        {
            let job_target =
                target::bits_to_target(rebuilt.job_bits).ok_or(RejectReason::BadTarget)?;
            if job_target > node_target {
                return Err(RejectReason::BadTarget);
            }
        }
        Ok(())
    }

    fn check_share(
        &self,
        s: &PowSubmit,
        rebuilt: &RebuiltShare,
        now: u64,
    ) -> Result<(), RejectReason> {
        if !rebuilt.is_block
            && let Some(tip) = self.tip
            && rebuilt.prev_hash != tip
            && !self.within_tip_grace(rebuilt.prev_hash, now)
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
        if !self.policy.require_split
            || s.subsidy_only
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
        let rebuilt = self.rebuild(s, abw)?;
        let meets_share_target = target::meets_target(
            &rebuilt.raw_pow_hash,
            &target::target_for_exponent(s.target_byte),
        );
        match self.check_rebuilt(s, &rebuilt, now, meets_share_target) {
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
        self.check_job_target(rebuilt)?;
        if meets_share_target || rebuilt.is_block {
            self.install_sections(s)?;
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

fn meets_own_bits(rebuilt: &RebuiltShare) -> bool {
    target::bits_to_target(rebuilt.job_bits)
        .is_some_and(|t| target::meets_target(&rebuilt.block_hash, &t))
}
