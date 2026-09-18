//! A job: one template, the two coinbases work may commit to, and the header fields every share on
//! it shares. The header before the miner's nonces is computed once per target byte and kept, since
//! every mining.notify carries a hash of it.

pub mod builder;

use crate::datum::abw::AbwAssignment;
use crate::template::Template;
use ratum::bitcoin::transaction::TxOut;
use ratum::datum::coinbase::BuiltCoinbase;
use ratum::datum::messages::share::{
    self, COINBASE_ID_SUBSIDY_ONLY, HEADER_EXTRANONCE_SIZE, JobSection,
};
use ratum::header::{self, BlockHeaderV2, SIA_WORDS_LEN};
use ratum::lock;
use ratum::target::Target;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Which of a job's two coinbases a piece of work commits to, and the coinbase id the
/// DATUM share carries for it.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum CoinbaseKind {
    Pooled,
    SubsidyOnly,
}

impl CoinbaseKind {
    const POOLED_WIRE_ID: u8 = 1;

    pub fn wire_id(self) -> u8 {
        match self {
            Self::Pooled => Self::POOLED_WIRE_ID,
            Self::SubsidyOnly => COINBASE_ID_SUBSIDY_ONLY,
        }
    }
}

pub struct Job {
    pub serial: u64,
    pub slot: u8,
    pub stratum_job_id: String,
    pub template: Arc<Template>,
    pub block_target: Target,
    pub prevblock_hidden: [u8; 32],
    /// The job section a share on this job carries to the pool, from which the gateway
    /// computes the header the same way the pool does.
    pub job_section: JobSection,
    pub pooled_coinbase: BuiltCoinbase,
    pub subsidy_only_coinbase: BuiltCoinbase,
    pub coinbaser_outputs: Vec<TxOut>,
    pub pool_payout_script: Vec<u8>,
    pub is_datum_job: bool,
    pub abw: Option<AbwAssignment>,
    pub created_at: Instant,
    pub stale_prevblock: AtomicBool,
    commitments: Mutex<HashMap<(CoinbaseKind, u8), H2Commitment>>,
}

/// The header of a coinbase and target byte before the miner's nonces and extranonce, and
/// its H2, which the mining.notify carries.
#[derive(Clone, Debug)]
pub struct H2Commitment {
    pub header: BlockHeaderV2,
    pub h2: [u8; 32],
}

impl Job {
    pub fn coinbase(&self, kind: CoinbaseKind) -> &BuiltCoinbase {
        match kind {
            CoinbaseKind::Pooled => &self.pooled_coinbase,
            CoinbaseKind::SubsidyOnly => &self.subsidy_only_coinbase,
        }
    }

    /// The sia ntime field of every job on this template: its curtime in the low word.
    pub fn ntime_hex(&self) -> String {
        hex::encode(self.template.curtime.to_le_bytes())
    }

    pub fn is_stale_prevblock(&self) -> bool {
        self.stale_prevblock.load(Ordering::Relaxed)
    }

    pub fn full_coinbase(&self, kind: CoinbaseKind, target_byte: u8) -> Option<Vec<u8>> {
        self.job_section.coinbase_tx(&self.coinbase(kind).section, target_byte)
    }

    fn hash_stages(&self, h: &BlockHeaderV2) -> header::HashStages {
        match self.abw {
            Some(a) => h.hash_stages_with_key_hash(a.key_hash),
            None => h.hash_stages(),
        }
    }

    pub fn raw_pow_hash(&self, h: &BlockHeaderV2) -> [u8; 32] {
        h.raw_pow_hash(&self.hash_stages(h))
    }

    /// The commitment for the coinbase and target byte, computed once and kept. The lock is
    /// released while it is computed, so two connections reaching the same entry together
    /// compute it twice rather than one waiting on three hashes of the other's.
    pub fn commitment(&self, kind: CoinbaseKind, target_byte: u8) -> Option<H2Commitment> {
        if let Some(c) = lock(&self.commitments).get(&(kind, target_byte)) {
            return Some(c.clone());
        }
        let tx = self.full_coinbase(kind, target_byte)?;
        let subsidy_only = kind == CoinbaseKind::SubsidyOnly;
        let header = self.job_section.header(
            self.template.version as i32,
            self.template.curtime as u32,
            self.job_section.merkle_root(&tx, subsidy_only),
            subsidy_only,
            target_byte,
            self.abw.is_some(),
        )?;
        let c = H2Commitment { h2: self.hash_stages(&header).h2, header };
        lock(&self.commitments).insert((kind, target_byte), c.clone());
        Some(c)
    }

    pub fn header(
        &self,
        kind: CoinbaseKind,
        target_byte: u8,
        extranonce: [u8; HEADER_EXTRANONCE_SIZE],
        sia_ntime: [u8; SIA_WORDS_LEN],
        sia_nonce: [u8; SIA_WORDS_LEN],
    ) -> Option<BlockHeaderV2> {
        let mut h = self.commitment(kind, target_byte)?.header;
        h.extranonce = extranonce;
        share::set_sia_fields(&mut h, &sia_ntime, &sia_nonce);
        Some(h)
    }
}

/// A job served to miners, and which of its two coinbases that work commits to. A new tip
/// publishes one job twice, as subsidy-only empty work and then as the pooled work its
/// coinbase pays, so `sequence` counts publications and `job.serial` counts jobs: the two
/// publications of one job carry one `job.serial` and two `sequence` numbers, and a
/// connection that has sent the first has not yet sent the second.
#[derive(Clone)]
pub struct Publication {
    pub job: Arc<Job>,
    pub kind: CoinbaseKind,
    pub sequence: u64,
}

/// The jobs a share may name by slot, and the work served to new connections, under one
/// lock. A job is dropped once it is older than `keep`, which releases its template and the
/// transactions in it: the slots number `datum.protocol_job_slots` (256 by default, the id
/// space the protocol carries), while the jobs that can still be used span the stale window
/// alone.
pub struct JobTable(Mutex<Jobs>);

struct Jobs {
    slots: Vec<Option<Arc<Job>>>,
    current: Option<Publication>,
    published: u64,
    keep: Duration,
}

impl JobTable {
    pub fn new(slots: usize, keep: Duration) -> Self {
        Self(Mutex::new(Jobs { slots: vec![None; slots], current: None, published: 0, keep }))
    }

    /// Installs the job in its slot, drops the jobs past `keep`, and makes it the work
    /// served. Subsidy-only work announces a new tip, so every job already installed is
    /// marked as building on a stale previous block.
    pub fn publish(&self, job: Arc<Job>, kind: CoinbaseKind) {
        let mut jobs = lock(&self.0);
        if kind == CoinbaseKind::SubsidyOnly {
            for other in jobs.slots.iter().flatten() {
                other.stale_prevblock.store(true, Ordering::Relaxed);
            }
        }
        let keep = jobs.keep;
        for slot in &mut jobs.slots {
            if slot.as_ref().is_some_and(|held| held.created_at.elapsed() > keep) {
                *slot = None;
            }
        }
        if let Some(slot) = jobs.slots.get_mut(usize::from(job.slot)) {
            *slot = Some(Arc::clone(&job));
        }
        jobs.published += 1;
        jobs.current = Some(Publication { job, kind, sequence: jobs.published });
    }

    /// The job installed in the slot, or none while the slot is empty or out of range.
    pub fn at(&self, slot: u8) -> Option<Arc<Job>> {
        lock(&self.0).slots.get(usize::from(slot))?.clone()
    }

    pub fn current(&self) -> Option<Publication> {
        lock(&self.0).current.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{config, template};
    use crate::job::builder::{JobInputs, build};

    const KEEP: Duration = Duration::from_secs(320);

    /// The job of serial `serial`, built `age` ago; its slot is the serial's, as the builder
    /// derives it.
    fn aged(serial: u64, age: Duration) -> Arc<Job> {
        let mut job = build(&config(), JobInputs::new(serial, Arc::new(template()))).unwrap();
        job.created_at = Instant::now() - age;
        Arc::new(job)
    }

    fn publish(table: &JobTable, job: Arc<Job>) {
        table.publish(job, CoinbaseKind::Pooled);
    }

    #[test]
    fn a_job_is_served_until_it_is_older_than_the_retention_window() {
        let table = JobTable::new(6, KEEP);
        publish(&table, aged(0, KEEP - Duration::from_secs(1)));
        publish(&table, aged(1, Duration::ZERO));
        assert!(table.at(0).is_some(), "a job inside the window is still resolved");
        assert_eq!(table.current().map(|p| p.job.serial), Some(1));

        publish(&table, aged(2, Duration::ZERO));
        assert!(table.at(0).is_some(), "and stays until it is past the window");

        let table = JobTable::new(6, KEEP);
        publish(&table, aged(0, KEEP + Duration::from_secs(1)));
        assert!(table.at(0).is_some(), "the job just installed is kept whatever its age");
        publish(&table, aged(1, Duration::ZERO));
        assert!(table.at(0).is_none(), "the next installation drops it and its template");
        assert!(table.at(1).is_some());
    }

    #[test]
    fn a_new_tip_marks_the_jobs_it_replaces_stale() {
        let table = JobTable::new(6, KEEP);
        publish(&table, aged(0, Duration::ZERO));
        let kept = table.at(0).expect("slot 0");
        assert!(!kept.is_stale_prevblock());
        table.publish(aged(1, Duration::ZERO), CoinbaseKind::SubsidyOnly);
        assert!(kept.is_stale_prevblock());
    }

    /// The empty work of a new tip and the pooled work that follows it are one job served
    /// twice, so the publication sequence moves where the job serial does not.
    #[test]
    fn one_job_published_under_both_coinbases_is_two_publications() {
        let table = JobTable::new(6, KEEP);
        let job = aged(0, Duration::ZERO);
        table.publish(Arc::clone(&job), CoinbaseKind::SubsidyOnly);
        let empty_work = table.current().expect("published");
        table.publish(job, CoinbaseKind::Pooled);
        let pooled = table.current().expect("published");
        assert_eq!(empty_work.job.serial, pooled.job.serial, "one job");
        assert_ne!(empty_work.sequence, pooled.sequence, "two publications");
        assert_eq!(pooled.kind, CoinbaseKind::Pooled);
        assert!(Arc::ptr_eq(&empty_work.job, &pooled.job), "and one allocation");
    }
}
