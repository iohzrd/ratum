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

    /// The sia ntime field of every job on this template, as the C gateway writes it: zero in
    /// the low word and curtime in the high word, which the header carries as a time offset
    /// of 0 and nonce3 equal to curtime (`share::set_sia_fields`). The block time is the
    /// template's curtime either way: the header's time is curtime, and the time offset is
    /// added to it only under `FLAG_USE_TIME_OFFSET`, which this gateway never sets.
    pub fn ntime_hex(&self) -> String {
        hex::encode(header::sia_words(0, self.template.curtime as u32))
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
    /// The previous block of the newest template work was built from, which `set_tip`
    /// records; none before the first.
    tip: Option<[u8; 32]>,
}

impl JobTable {
    pub fn new(slots: usize, keep: Duration) -> Self {
        Self(Mutex::new(Jobs {
            slots: vec![None; slots],
            current: None,
            published: 0,
            keep,
            tip: None,
        }))
    }

    /// Records the previous block the newest template builds on, before any job is built
    /// from it. From then on `publish` refuses a job on any other previous block: a job
    /// built from an older template (the pooled job of a coinbaser answer that arrived
    /// after the tip moved) is never served after the new tip's work.
    pub fn set_tip(&self, prev_hash: [u8; 32]) {
        lock(&self.0).tip = Some(prev_hash);
    }

    /// The previous block `set_tip` last recorded.
    pub fn tip(&self) -> Option<[u8; 32]> {
        lock(&self.0).tip
    }

    /// Installs the job in its slot, drops the jobs past `keep`, and makes it the work
    /// served. Returns false, and changes nothing, when the job builds on a previous block
    /// other than the tip `set_tip` recorded. Subsidy-only work announces a new tip, so every
    /// job already installed is marked as building on a stale previous block; pooled work
    /// marks the installed jobs on another previous block, which is how a tip served first as
    /// pooled work (its priority job was not built) ends the work on the tip before it.
    pub fn publish(&self, job: Arc<Job>, kind: CoinbaseKind) -> bool {
        let mut jobs = lock(&self.0);
        let prev_hash = job.template.prev_hash;
        if jobs.tip.is_some_and(|tip| tip != prev_hash) {
            return false;
        }
        for other in jobs.slots.iter().flatten() {
            if kind == CoinbaseKind::SubsidyOnly || other.template.prev_hash != prev_hash {
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
        true
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
        assert!(table.publish(job, CoinbaseKind::Pooled));
    }

    /// The job of serial `serial` on a template whose previous block is `prev_hash`.
    fn on_tip(serial: u64, prev_hash: [u8; 32]) -> Arc<Job> {
        let t = Template { prev_hash, ..template() };
        Arc::new(build(&config(), JobInputs::new(serial, Arc::new(t))).unwrap())
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
        assert!(table.publish(aged(1, Duration::ZERO), CoinbaseKind::SubsidyOnly));
        assert!(kept.is_stale_prevblock());
    }

    /// Pooled work on the tip it replaces keeps every earlier job valid, which is what an
    /// anti-block-withholding refresh publishes; pooled work on another previous block marks
    /// the jobs before it stale even when no empty work announced that block.
    #[test]
    fn pooled_work_marks_stale_only_the_jobs_on_another_previous_block() {
        let table = JobTable::new(6, KEEP);
        publish(&table, on_tip(0, [0; 32]));
        let first = table.at(0).expect("slot 0");
        publish(&table, on_tip(1, [0; 32]));
        assert!(!first.is_stale_prevblock(), "the same tip");

        publish(&table, on_tip(2, [0x11; 32]));
        assert!(first.is_stale_prevblock(), "a new tip served as pooled work alone");
        let second = table.at(1).expect("slot 1");
        assert!(second.is_stale_prevblock());
        assert!(!table.at(2).expect("slot 2").is_stale_prevblock());
    }

    /// A job built from an older template, published after the tip moved, is refused: it
    /// is neither installed nor served, and the new tip's work stays current.
    #[test]
    fn a_job_on_a_previous_block_other_than_the_tip_is_refused() {
        let table = JobTable::new(6, KEEP);
        table.set_tip([0; 32]);
        publish(&table, on_tip(0, [0; 32]));
        table.set_tip([0x11; 32]);
        assert!(table.publish(on_tip(1, [0x11; 32]), CoinbaseKind::SubsidyOnly));

        let late = on_tip(2, [0; 32]);
        assert!(!table.publish(Arc::clone(&late), CoinbaseKind::Pooled));
        assert!(table.at(late.slot).is_none(), "not installed");
        let current = table.current().expect("the new tip's work");
        assert_eq!(current.job.serial, 1);
        assert_eq!(current.kind, CoinbaseKind::SubsidyOnly);
        assert!(!current.job.is_stale_prevblock());
        assert_eq!(table.tip(), Some([0x11; 32]));
    }

    /// The notify's ntime is the C gateway's: curtime in the high word. A miner that returns
    /// it unchanged submits a header with a time offset of 0 and nonce3 equal to curtime,
    /// whose block time is curtime on the node and in the pool's rebuild of the share, and
    /// whose hash the pool computes as the gateway does.
    #[test]
    fn the_notified_ntime_is_the_c_gateways_and_keeps_the_block_time() {
        use ratum::datum::messages::share::{Blake2bSection, PowSubmit, share_extranonce};
        let job = aged(0, Duration::ZERO);
        let curtime = job.template.curtime as u32;
        assert_eq!(job.ntime_hex(), format!("00000000{}", hex::encode(curtime.to_le_bytes())));

        let ntime: [u8; SIA_WORDS_LEN] = hex::decode(job.ntime_hex()).unwrap().try_into().unwrap();
        let (kind, target_byte) = (CoinbaseKind::Pooled, 14);
        let h = job.header(kind, target_byte, [0; 16], ntime, header::sia_words(1, 2)).unwrap();
        assert_eq!((h.time_offset, h.nonce3, h.time, h.flags), (0, curtime, curtime, 0));
        let wire = h.serialize();
        let time_on_wire_at = 4 + 32 + 32;
        assert_eq!(&wire[time_on_wire_at..time_on_wire_at + 4], &curtime.to_le_bytes());
        assert_eq!(BlockHeaderV2::deserialize(&wire).as_ref(), Some(&h), "the node's block time");

        let blake2b = Blake2bSection::from_header(&h);
        let submit = PowSubmit {
            job_id: job.slot,
            coinbase_id: kind.wire_id(),
            is_block: false,
            subsidy_only: false,
            quickdiff: false,
            target_byte,
            ntime: blake2b.time_fields().0,
            nonce: h.nonce,
            version: header::V2_FLAG | h.version as u32,
            extranonce: share_extranonce(&h.extranonce).unwrap(),
            username: "bcrt1qexample".into(),
            use_time_offset: false,
            job: None,
            coinbase: None,
            blake2b,
            abw_slot: None,
        };
        assert_eq!(submit.ntime, 0, "the share's ntime is the time offset word, as C sends it");
        assert_eq!(submit.block_time(), curtime);
        let rebuilt = submit.header(&job.job_section, &h.merkle_root, None).unwrap();
        assert_eq!(rebuilt, h);
        assert_eq!(rebuilt.pow_hashes().raw_pow_hash, job.raw_pow_hash(&h));
    }

    /// The empty work of a new tip and the pooled work that follows it are one job served
    /// twice, so the publication sequence moves where the job serial does not.
    #[test]
    fn one_job_published_under_both_coinbases_is_two_publications() {
        let table = JobTable::new(6, KEEP);
        let job = aged(0, Duration::ZERO);
        assert!(table.publish(Arc::clone(&job), CoinbaseKind::SubsidyOnly));
        let empty_work = table.current().expect("published");
        assert!(table.publish(job, CoinbaseKind::Pooled));
        let pooled = table.current().expect("published");
        assert_eq!(empty_work.job.serial, pooled.job.serial, "one job");
        assert_ne!(empty_work.sequence, pooled.sequence, "two publications");
        assert_eq!(pooled.kind, CoinbaseKind::Pooled);
        assert!(Arc::ptr_eq(&empty_work.job, &pooled.job), "and one allocation");
    }
}
