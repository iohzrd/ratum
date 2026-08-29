//! A stratum job: one template with its coinbases, merkle branches, and the version 2 header
//! commitments a miner receives. Built by `Builder`, which holds the counters a job's
//! identifiers come from.

use crate::coinbase::{self, Coinbase};
use crate::config::Config;
use crate::datum::PoolConfig;
use crate::template::Template;
use ratum::datum::messages::{CoinbaseOutput, CoinbaserResponse};
use ratum::datum::share::EXTRANONCE_SIZE;
use ratum::header::{self, HeaderV2};
use ratum::target::{self, Target};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub use ratum::datum::share::{COINBASE_ID_SUBSIDY_ONLY as COINBASE_SUBSIDY_ONLY, MAX_JOBS};
pub const JOB_INDEX_XOR: u16 = 0xC0DE;

pub struct Job {
    /// Counts every job built; its low byte is the ring index.
    pub serial: u64,
    pub global_index: u8,
    /// The 14 hex characters a notify's job id begins with.
    pub job_id: String,
    pub datum_slot: u8,
    pub template: Arc<Template>,
    /// The 64-bit job time as eight little-endian bytes, hex: the notify's `ntime`.
    pub ntime_hex: String,
    pub block_target: Target,
    pub prevblock_hidden: [u8; 32],
    pub merkle_branches: Vec<[u8; 32]>,
    pub target_pot_index: usize,
    pub coinbases: Vec<Coinbase>,
    pub subsidy_only: Coinbase,
    pub coinbaser_id: u8,
    pub coinbaser_outputs: Vec<CoinbaseOutput>,
    pub pool_addr_script: Vec<u8>,
    pub is_datum_job: bool,
    pub is_new_block: bool,
    pub created: Instant,
    pub stale_prevblock: AtomicBool,
    /// `commitment` by `(coinbase id, PoT byte)`: the same pair is requested by every
    /// connection at that difficulty, on every notify and every share.
    commitments: Mutex<HashMap<(u8, u8), Commitment>>,
}

#[derive(Clone, Debug)]
pub struct Commitment {
    pub merkle_root: [u8; 32],
    pub h2: [u8; 32],
    pub txcount: u16,
}

/// One output of the generation transaction as the API reports it: the pool's split, then
/// the remainder to the pool script.
pub struct PayoutRow {
    pub value: u64,
    pub script: Vec<u8>,
    pub remainder: bool,
}

impl Job {
    pub fn coinbase(&self, id: u8) -> Option<&Coinbase> {
        if id == COINBASE_SUBSIDY_ONLY {
            Some(&self.subsidy_only)
        } else {
            self.coinbases.get(id as usize)
        }
    }

    pub fn is_stale_prevblock(&self) -> bool {
        self.stale_prevblock.load(Ordering::Relaxed)
    }

    /// The transaction a share commits to: the coinbase with the PoT byte written in.
    pub fn full_coinbase(&self, id: u8, pot: u8) -> Option<Vec<u8>> {
        let mut tx = self.coinbase(id)?.assemble(&[0u8; EXTRANONCE_SIZE]);
        *tx.get_mut(self.target_pot_index)? = pot;
        Some(tx)
    }

    /// The header fields the job fixes, before the miner's.
    fn header_base(&self, merkle_root: [u8; 32], txcount: u16) -> HeaderV2 {
        HeaderV2 {
            version: self.template.version as i32,
            prev_block: self.template.prev_hash,
            merkle_root,
            time: self.template.curtime as u32,
            bits: self.template.nbits,
            txcount,
            height: self.template.height as i32,
            ..Default::default()
        }
    }

    pub fn commitment(&self, id: u8, pot: u8) -> Option<Commitment> {
        if let Some(c) = ratum::lock(&self.commitments).get(&(id, pot)) {
            return Some(c.clone());
        }
        let tx = self.full_coinbase(id, pot)?;
        let cb_hash = ratum::bitcoin::sha256d(&tx);
        let subsidy_only = id == COINBASE_SUBSIDY_ONLY;
        let branches: &[[u8; 32]] = if subsidy_only { &[] } else { &self.merkle_branches };
        let merkle_root = ratum::bitcoin::merkle_root(&cb_hash, branches);
        let txcount = if subsidy_only { 1 } else { self.template.txns.len() as u16 + 1 };
        let h2 = self.header_base(merkle_root, txcount).precompute().h2;
        let c = Commitment { merkle_root, h2, txcount };
        ratum::lock(&self.commitments).insert((id, pot), c.clone());
        Some(c)
    }

    /// The header a share names, from the fields the miner set.
    pub fn header(
        &self,
        id: u8,
        pot: u8,
        extranonce: [u8; 16],
        sia_nonce: [u8; 8],
        sia_ntime: [u8; 8],
    ) -> Option<HeaderV2> {
        let c = self.commitment(id, pot)?;
        let mut h = self.header_base(c.merkle_root, c.txcount);
        h.extranonce = extranonce;
        h.nonce = u32::from_le_bytes(sia_nonce[..4].try_into().unwrap());
        h.nonce2 = u32::from_le_bytes(sia_nonce[4..].try_into().unwrap());
        h.time_offset = u32::from_le_bytes(sia_ntime[..4].try_into().unwrap());
        h.nonce3 = u32::from_le_bytes(sia_ntime[4..].try_into().unwrap());
        Some(h)
    }

    /// What the generation transaction pays: the coinbaser's outputs, then the remainder to
    /// the pool script when they do not take the whole value.
    pub fn payout_rows(&self) -> Vec<PayoutRow> {
        let mut rows: Vec<PayoutRow> = self
            .coinbaser_outputs
            .iter()
            .map(|o| PayoutRow { value: o.value, script: o.script.clone(), remainder: false })
            .collect();
        let paid: u64 = self.coinbaser_outputs.iter().map(|o| o.value).sum();
        if paid < self.template.coinbase_value {
            rows.push(PayoutRow {
                value: self.template.coinbase_value - paid,
                script: self.pool_addr_script.clone(),
                remainder: true,
            });
        }
        rows
    }
}

/// The merkle branches of the coinbase's path, from the other transactions' txids, with the
/// odd-level duplication of Bitcoin's tree.
pub fn merkle_branches(txids: &[[u8; 32]]) -> Vec<[u8; 32]> {
    if txids.is_empty() {
        return Vec::new();
    }
    let mut level: Vec<Option<[u8; 32]>> = Vec::with_capacity(txids.len() + 1);
    level.push(None);
    level.extend(txids.iter().map(|t| Some(*t)));
    let mut branches = Vec::new();
    let mut combined = [0u8; 64];
    while level.len() > 1 {
        branches.push(level[1].expect("a sibling on the coinbase path is known"));
        if level.len() % 2 == 1 {
            let last = *level.last().unwrap();
            level.push(last);
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            match (pair[0], pair[1]) {
                (Some(a), Some(b)) => {
                    combined[..32].copy_from_slice(&a);
                    combined[32..].copy_from_slice(&b);
                    next.push(Some(ratum::bitcoin::sha256d(&combined)));
                }
                _ => next.push(None),
            }
        }
        level = next;
    }
    branches
}

/// Why a job could not be built. The first two hold for every template until the pool's
/// configuration or the file changes; the others are the template's.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BuildError {
    #[error("pool payout script of {0} bytes")]
    PayoutScriptSize(usize),
    #[error("{0}")]
    Tagging(String),
    #[error("{0} merkle branches; the protocol carries at most 24")]
    TooManyBranches(usize),
    #[error("the template's bits do not decode")]
    BadBits,
}

/// The seven coinbases of a job and what they share.
struct CoinbaseSet {
    coinbases: Vec<Coinbase>,
    subsidy_only: Coinbase,
    target_pot_index: usize,
    /// The coinbaser outputs the widest size class included.
    widest: Vec<CoinbaseOutput>,
}

pub struct Builder {
    serial: u64,
    enprefix: u16,
    datum_slot: u8,
    config: Arc<Config>,
}

impl Builder {
    pub fn new(config: Arc<Config>) -> Self {
        Builder { serial: 0, enprefix: 0, datum_slot: 0, config }
    }

    /// Build a job. `pool` is the connected pool's configuration, `coinbaser` its split for
    /// this template. `new_block` marks the first job on a new tip, which carries the
    /// subsidy-only coinbase for the empty work sent while the full one is built.
    pub fn build(
        &mut self,
        template: Arc<Template>,
        new_block: bool,
        pool: Option<&PoolConfig>,
        coinbaser: Option<CoinbaserResponse>,
    ) -> Result<Job, BuildError> {
        let c = &self.config;
        let serial = self.serial;
        self.serial += 1;
        let global_index = (serial % MAX_JOBS as u64) as u8;
        let enprefix = self.enprefix ^ 0xB10C;
        self.enprefix = self.enprefix.wrapping_add(1);
        let slots = c.datum.protocol_job_slots as u32;
        let datum_slot = self.datum_slot;
        self.datum_slot = ((u32::from(self.datum_slot) + 1) % slots) as u8;

        let (pool_addr_script, prime_id, tag_primary) = match pool {
            Some(p) => (p.payout_script.clone(), p.prime_id, p.coinbase_tag.as_str()),
            None => (c.pool_output_script.clone(), 0, c.mining.coinbase_tag_primary.as_str()),
        };
        if pool_addr_script.is_empty() || pool_addr_script.len() > 64 {
            return Err(BuildError::PayoutScriptSize(pool_addr_script.len()));
        }
        let (script, pot_in_script) = coinbase::script_sig(&coinbase::Tagging {
            height: template.height,
            activation_height: c.mining.blake2b_activation_height,
            headline: &c.mining.blake2b_headline,
            tag_primary,
            tag_secondary: &c.mining.coinbase_tag_secondary,
            unique_id: (c.mining.coinbase_unique_id & 0xffff) as u16,
            prime_id,
            datum_active: pool.is_some(),
        })
        .map_err(BuildError::Tagging)?;
        if template.height == c.mining.blake2b_activation_height && new_block {
            log::info!(
                "Height {} activates BLAKE2b: putting the headline in the coinbase instead of the tags",
                template.height
            );
        }

        let (coinbaser_id, outputs) = filter_coinbaser(&template, coinbaser);
        let set =
            coinbase_set(&template, &script, pot_in_script, enprefix, &pool_addr_script, &outputs);

        let txids: Vec<[u8; 32]> = template.txns.iter().map(|t| t.txid).collect();
        let merkle_branches = merkle_branches(&txids);
        if merkle_branches.len() > ratum::datum::share::MAX_MERKLE_BRANCHES {
            return Err(BuildError::TooManyBranches(merkle_branches.len()));
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()) as u32;
        let job_id =
            format!("{now:08x}{global_index:02x}{:04x}", u16::from(global_index) ^ JOB_INDEX_XOR);
        Ok(Job {
            serial,
            global_index,
            job_id,
            datum_slot,
            ntime_hex: hex::encode(template.curtime.to_le_bytes()),
            block_target: target::bits_to_target(template.nbits).ok_or(BuildError::BadBits)?,
            prevblock_hidden: header::prevblock_hidden(&template.prev_hash),
            merkle_branches,
            target_pot_index: set.target_pot_index,
            coinbases: set.coinbases,
            subsidy_only: set.subsidy_only,
            coinbaser_id,
            coinbaser_outputs: set.widest,
            pool_addr_script,
            is_datum_job: pool.is_some(),
            is_new_block: new_block,
            created: Instant::now(),
            stale_prevblock: AtomicBool::new(false),
            commitments: Mutex::new(HashMap::new()),
            template,
        })
    }
}

/// The coinbaser's id and outputs, less any output script over the `reduced_data` limit when
/// the template enforces it.
fn filter_coinbaser(
    template: &Template,
    coinbaser: Option<CoinbaserResponse>,
) -> (u8, Vec<CoinbaseOutput>) {
    let Some(r) = coinbaser else { return (0, Vec::new()) };
    let (kept, dropped): (Vec<_>, Vec<_>) = r.outputs.into_iter().partition(|o| {
        !template.reduced_data || ratum::bitcoin::output_script_size_is_valid(&o.script)
    });
    for o in dropped {
        log::warn!(
            "Coinbaser sent a {} byte output script, over the reduced_data limit for block {}. Leaving that output out of the generation txn.",
            o.script.len(),
            template.height
        );
    }
    (r.coinbaser_id, kept)
}

/// The subsidy-only coinbase and the six size classes (`MAX_COINBASE_TYPES`), with the PoT
/// byte at one offset in all of them.
fn coinbase_set(
    template: &Template,
    script: &[u8],
    pot_in_script: usize,
    enprefix: u16,
    pool_script: &[u8],
    outputs: &[CoinbaseOutput],
) -> CoinbaseSet {
    let params = |outs, budget, force, subsidy_only| coinbase::Params {
        script_sig: script,
        pot_index_in_script: pot_in_script,
        enprefix,
        witness_commitment: if subsidy_only { None } else { Some(&template.witness_commitment) },
        pool_script,
        coinbase_value: if subsidy_only {
            template.coinbase_value - template.totals.fee
        } else {
            template.coinbase_value
        },
        outputs: outs,
        output_budget: budget,
        force_op_return_extranonce: force,
    };
    let (subsidy_only, target_pot_index, _) = coinbase::build(&params(&[], 0, false, true));
    let mut coinbases = Vec::with_capacity(coinbase::TYPE_MAX_SIZE.len());
    let mut widest: Vec<CoinbaseOutput> = Vec::new();
    for (ty, &max_size) in coinbase::TYPE_MAX_SIZE.iter().enumerate() {
        let force = coinbase::TYPE_FORCES_OP_RETURN[ty];
        let fixed = 119
            + pool_script.len()
            + script.len()
            + if force || script.len() > 85 { 10 } else { 0 };
        let budget = if ty == 0 || outputs.is_empty() {
            0
        } else {
            coinbase::fit_to_template(max_size, fixed, template)
        };
        let (cb, pot, included) = coinbase::build(&params(outputs, budget, force, false));
        debug_assert_eq!(pot, target_pot_index);
        if included.len() > widest.len() {
            widest = included;
        }
        coinbases.push(cb);
    }
    CoinbaseSet { coinbases, subsidy_only, target_pot_index, widest }
}

/// What a stratum job id names: the 14-character job id, the job's global index, and the
/// suffix and prefix the notify added.
///
/// ```text
/// {job_id}{cb:02x}      a standard job, with the coinbase class the miner is served
/// Q{job_id}{cb:02x}     a quick-raise job, whose difficulty the connection keeps apart
/// N{job_id}ff           new-block empty work, on the subsidy-only coinbase
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobRef {
    pub global_index: u8,
    pub quickdiff: bool,
    pub empty: bool,
    pub coinbase: u8,
}

impl JobRef {
    /// The id `mining.notify` carries for `job`.
    pub fn notify_id(&self, job: &Job) -> String {
        let cb = self.coinbase;
        if self.quickdiff {
            format!("Q{}{cb:02x}", job.job_id)
        } else if self.empty {
            format!("N{}ff", job.job_id)
        } else {
            format!("{}{cb:02x}", job.job_id)
        }
    }

    /// Parse the id a `mining.submit` names; also the 14-character job id it carries.
    pub fn parse(s: &str) -> Option<(JobRef, &str)> {
        let (quickdiff, empty, rest) = match s.len() {
            16 => (false, false, s),
            17 if s.starts_with('Q') => (true, false, &s[1..]),
            17 if s.starts_with('N') => (false, true, &s[1..]),
            _ => return None,
        };
        let job_id = &rest[..14];
        let global_index = global_index_of(job_id)?;
        let coinbase = u8::from_str_radix(&rest[14..16], 16).ok()?;
        if empty && coinbase != COINBASE_SUBSIDY_ONLY {
            return None;
        }
        Some((JobRef { global_index, quickdiff, empty, coinbase }, job_id))
    }
}

/// The stratum job id's global index: characters 10..14 of the 14-character id, XORed.
pub fn global_index_of(job_id: &str) -> Option<u8> {
    let raw = u16::from_str_radix(job_id.get(10..14)?, 16).ok()?;
    let idx = raw ^ JOB_INDEX_XOR;
    if idx as usize >= MAX_JOBS { None } else { Some(idx as u8) }
}

/// An eight-byte Sia stratum field: sixteen hex characters, or eight for a 32-bit value the
/// miner sent alone, which fills the low four bytes.
pub fn parse_sia_field(s: &str) -> Option<[u8; 8]> {
    match s.len() {
        16 => hex::decode(s).ok()?.try_into().ok(),
        8 => {
            let v = u32::from_str_radix(s, 16).ok()?;
            let mut out = [0u8; 8];
            out[..4].copy_from_slice(&v.to_le_bytes());
            Some(out)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branches_reproduce_the_tree_root() {
        let cb = [0x11u8; 32];
        for n in [1usize, 2, 3, 4, 5, 6, 7, 8, 9, 100] {
            let txids: Vec<[u8; 32]> = (0..n).map(|i| [i as u8 + 1; 32]).collect();
            let branches = merkle_branches(&txids);
            let from_branches = ratum::bitcoin::merkle_root(&cb, &branches);
            let mut all = vec![cb];
            all.extend_from_slice(&txids);
            let (root, _) = ratum::bitcoin::merkle_root_of(&all).unwrap();
            assert_eq!(from_branches, root, "{n} transactions");
        }
        assert!(merkle_branches(&[]).is_empty());
    }

    #[test]
    fn job_ids_carry_the_global_index() {
        let id = format!("{:08x}{:02x}{:04x}", 0x6625a3d5u32, 0x3c, 0x3c ^ JOB_INDEX_XOR);
        assert_eq!(global_index_of(&id), Some(0x3c));
        assert_eq!(global_index_of("short"), None);
    }

    #[test]
    fn job_refs_round_trip_through_the_notify_id() {
        let job_id = format!("{:08x}{:02x}{:04x}", 0x6625a3d5u32, 0x3c, 0x3c ^ JOB_INDEX_XOR);
        let job = crate::template::tests::job_with_id(&job_id);
        for r in [
            JobRef { global_index: 0x3c, quickdiff: false, empty: false, coinbase: 2 },
            JobRef { global_index: 0x3c, quickdiff: true, empty: false, coinbase: 5 },
            JobRef { global_index: 0x3c, quickdiff: false, empty: true, coinbase: 0xff },
        ] {
            let id = r.notify_id(&job);
            let (parsed, carried) = JobRef::parse(&id).unwrap();
            assert_eq!(parsed, r, "{id}");
            assert_eq!(carried, job_id);
        }
        assert_eq!(JobRef::parse("N6625a3d53cc0e202"), None, "empty work is subsidy-only");
        assert_eq!(JobRef::parse("X6625a3d53cc0e2ff"), None);
        assert_eq!(JobRef::parse("6625a3d53cc0e2"), None);
    }

    #[test]
    fn sia_fields_take_both_widths() {
        assert_eq!(parse_sia_field("0100000002000000"), Some([1, 0, 0, 0, 2, 0, 0, 0]));
        assert_eq!(parse_sia_field("00000001"), Some([1, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(parse_sia_field("0001"), None);
    }
}
