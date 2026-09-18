//! The job id a mining.notify carries and a mining.submit names: the job's creation time and slot,
//! the slot again masked, and a prefix naming which of the two coinbases the work commits to.

use crate::job::{CoinbaseKind, Job};
use ratum::datum::messages::share::MAX_JOBS;

const JOB_INDEX_XOR: u16 = 0xC0DE;
/// The leading characters of a stratum job id: the job's creation time.
pub const JOB_ID_TIME_CHARS: usize = 8;
const JOB_ID_CHARS: usize = 14;
const JOB_ID_INDEX_AT: std::ops::Range<usize> = 10..JOB_ID_CHARS;
const NOTIFY_ID_CHARS: usize = JOB_ID_CHARS + 2;
const QUICKDIFF_PREFIX: char = 'Q';
const EMPTY_WORK_PREFIX: char = 'N';

/// A job's stratum id: its creation time, its slot, and the slot again masked with
/// `JOB_INDEX_XOR`, which is what a submit is resolved by.
pub fn stratum_job_id(created_at: u32, slot: u8) -> String {
    format!("{created_at:08x}{slot:02x}{:04x}", u16::from(slot) ^ JOB_INDEX_XOR)
}

fn slot_of(stratum_job_id: &str) -> Option<u8> {
    let raw = u16::from_str_radix(stratum_job_id.get(JOB_ID_INDEX_AT)?, 16).ok()?;
    let idx = raw ^ JOB_INDEX_XOR;
    if idx as usize >= MAX_JOBS { None } else { Some(idx as u8) }
}

/// What a mining.notify carries besides the job: plain work, a quickdiff resend of the
/// current job, or the subsidy-only empty work sent on a new tip. The prefix decides the
/// coinbase the work commits to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotifyPrefix {
    Plain,
    Quickdiff,
    EmptyWork,
}

/// The prefix a job is first served under: subsidy-only work under its own, pooled work
/// plain. The inverse of `coinbase` on these two variants; a quickdiff resend is a later
/// notify of a job already served, so no coinbase maps to it.
impl From<CoinbaseKind> for NotifyPrefix {
    fn from(kind: CoinbaseKind) -> Self {
        match kind {
            CoinbaseKind::SubsidyOnly => Self::EmptyWork,
            CoinbaseKind::Pooled => Self::Plain,
        }
    }
}

impl NotifyPrefix {
    pub fn coinbase(self) -> CoinbaseKind {
        match self {
            Self::Plain | Self::Quickdiff => CoinbaseKind::Pooled,
            Self::EmptyWork => CoinbaseKind::SubsidyOnly,
        }
    }

    /// The job id a mining.notify of `job` with this prefix carries: the prefix character,
    /// the job's stratum id and the coinbase id.
    pub fn notify_id(self, job: &Job) -> String {
        let cb = self.coinbase().wire_id();
        match self {
            Self::Plain => format!("{}{cb:02x}", job.stratum_job_id),
            Self::Quickdiff => format!("{QUICKDIFF_PREFIX}{}{cb:02x}", job.stratum_job_id),
            Self::EmptyWork => format!("{EMPTY_WORK_PREFIX}{}{cb:02x}", job.stratum_job_id),
        }
    }
}

/// A submitted job id read back: the slot of the job it names and the prefix it was
/// notified with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotifyId {
    pub slot: u8,
    pub prefix: NotifyPrefix,
}

impl NotifyId {
    /// The notify id and the stratum job id inside it.
    pub fn parse(s: &str) -> Option<(Self, &str)> {
        const PREFIXED: usize = NOTIFY_ID_CHARS + 1;
        let (prefix, rest) = match s.len() {
            NOTIFY_ID_CHARS => (NotifyPrefix::Plain, s),
            PREFIXED if s.starts_with(QUICKDIFF_PREFIX) => (NotifyPrefix::Quickdiff, &s[1..]),
            PREFIXED if s.starts_with(EMPTY_WORK_PREFIX) => (NotifyPrefix::EmptyWork, &s[1..]),
            _ => return None,
        };
        let stratum_job_id = rest.get(..JOB_ID_CHARS)?;
        let slot = slot_of(stratum_job_id)?;
        let coinbase_id = u8::from_str_radix(rest.get(JOB_ID_CHARS..NOTIFY_ID_CHARS)?, 16).ok()?;
        if coinbase_id != prefix.coinbase().wire_id() {
            return None;
        }
        Some((Self { slot, prefix }, stratum_job_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_ids_carry_the_slot() {
        let id = stratum_job_id(0x6625a3d5, 0x3c);
        assert_eq!(id, format!("6625a3d53c{:04x}", 0x3c ^ JOB_INDEX_XOR));
        assert_eq!(slot_of(&id), Some(0x3c));
        assert_eq!(slot_of("short"), None);
    }

    #[test]
    fn job_refs_round_trip_through_the_notify_id() {
        let job_id = stratum_job_id(0x6625a3d5, 0x3c);
        let job = crate::fixtures::job_with_id(&job_id);
        for prefix in [NotifyPrefix::Plain, NotifyPrefix::Quickdiff, NotifyPrefix::EmptyWork] {
            let id = prefix.notify_id(&job);
            let (parsed, carried) = NotifyId::parse(&id).unwrap();
            assert_eq!(parsed, NotifyId { slot: 0x3c, prefix }, "{id}");
            assert_eq!(carried, job_id);
        }
        assert_eq!(NotifyId::parse("N6625a3d53cc0e202"), None, "empty work is subsidy-only");
        assert_eq!(NotifyId::parse("6625a3d53cc0e2ff"), None, "plain work is pooled");
        assert_eq!(NotifyId::parse("Q6625a3d53cc0e205"), None, "a quickdiff resend is pooled");
        assert_eq!(NotifyId::parse("X6625a3d53cc0e2ff"), None);
        assert_eq!(NotifyId::parse("6625a3d53cc0e2"), None);
    }
}
