//! A stratum job: one template with its coinbases, merkle branches, and the version 2 header
//! commitments a miner receives. Built by `Builder`, which holds the counters a job's
//! identifiers come from.

use crate::coinbase::{self, Coinbase};
use crate::config::Config;
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

/// The pool's 0x99 configuration, as the jobs are built from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolConfig {
    pub payout_script: Vec<u8>,
    /// u64 for the version 3 protocol; a version 1 config fills the low 32 bits.
    pub prime_id: u64,
    pub coinbase_tag: String,
    pub min_difficulty: u64,
    /// True when the config came from a version 3 message: the coinbase carries the 8-byte
    /// prime-id push and the session runs anti-block-withholding unless `abw_disabled`.
    pub protocol_v3: bool,
    /// The pool sent `CONFIG_FLAG_ABW_DISABLED`: it runs without anti-block-withholding, so
    /// pooled work is built with the null key and the gateway classifies blocks itself.
    pub abw_disabled: bool,
}

/// The active anti-block-withholding assignment: the wire slot and the pool's key
/// commitment. The gateway builds every header to commit to `key_hash`, without ever
/// holding the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Abw {
    pub slot: u8,
    pub key_hash: [u8; 32],
}

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
    /// The coinbase pooled work commits to: every dictated output that fits the template's room
    /// (`coinbase_set`), then the remainder to the pool script. Named by
    /// `coinbase::COINBASE_POOLED`.
    pub pooled: Coinbase,
    pub subsidy_only: Coinbase,
    pub coinbaser_id: u8,
    pub coinbaser_outputs: Vec<CoinbaseOutput>,
    pub pool_addr_script: Vec<u8>,
    pub is_datum_job: bool,
    /// The anti-block-withholding assignment this job commits to (version 3 protocol). `None`
    /// for a version 1 or solo job, whose headers use a zero XOR key. When set, the header
    /// commitments include `key_hash` and the PoT-derived clear bits, and shares carry the
    /// slot; the gateway cannot classify a block on such a job and never submits one.
    pub abw: Option<Abw>,
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
    /// The coinbase an id names: the subsidy-only one for `COINBASE_SUBSIDY_ONLY`, the pooled
    /// one for any other. The id carries no size class (see `coinbase::COINBASE_POOLED`);
    /// the stratum layer accepts only the pooled id on a share.
    pub fn coinbase(&self, id: u8) -> Option<&Coinbase> {
        if id == COINBASE_SUBSIDY_ONLY { Some(&self.subsidy_only) } else { Some(&self.pooled) }
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
    fn header_base(&self, merkle_root: [u8; 32], txcount: u16, pot: u8) -> HeaderV2 {
        HeaderV2 {
            version: self.template.version as i32,
            prev_block: self.template.prev_hash,
            merkle_root,
            time: self.template.curtime as u32,
            bits: self.template.nbits,
            txcount,
            height: self.template.height as i32,
            // Under an ABW assignment the header commits to the clear bits for this share's
            // difficulty; the key itself stays zero, since the gateway never holds it.
            xor_key_mask_clear_bits: self.abw.map_or(0, |_| ratum::datum::abw::clear_bits(pot)),
            ..Default::default()
        }
    }

    /// H2, the commitment the miner receives, computed with the ABW key hash when this job
    /// carries an assignment (the gateway commits to the pool's key without holding it) and
    /// from the header's own zero key otherwise.
    fn header_h2(&self, h: &HeaderV2) -> [u8; 32] {
        match self.abw {
            Some(a) => h.precompute_with_key_hash(a.key_hash).h2,
            None => h.precompute().h2,
        }
    }

    /// The proof-of-work hash a share is checked against. Under an ABW assignment this is the
    /// raw (unmasked) hash the miner computed: the gateway cannot apply the pool's mask, and
    /// the raw hash's top `32 + PoT` bits, which the share check reads, are what the mask
    /// leaves clear. Without an assignment it is the final hash (the mask is the identity).
    pub fn share_pow_hash(&self, h: &HeaderV2) -> [u8; 32] {
        match self.abw {
            Some(a) => {
                let pre = h.precompute_with_key_hash(a.key_hash);
                let input = h.asic_input_with(&pre.hash1, &pre.h2);
                ratum::header::blake2b_256(&input)
            }
            None => h.hash_components().result,
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
        let base = self.header_base(merkle_root, txcount, pot);
        let h2 = self.header_h2(&base);
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
        let mut h = self.header_base(c.merkle_root, c.txcount, pot);
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

/// The two coinbases of a job and what they share.
struct CoinbaseSet {
    pooled: Coinbase,
    subsidy_only: Coinbase,
    target_pot_index: usize,
    /// The coinbaser outputs the pooled coinbase includes.
    included: Vec<CoinbaseOutput>,
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
        abw: Option<Abw>,
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
            tag_primary,
            tag_secondary: &c.mining.coinbase_tag_secondary,
            unique_id: (c.mining.coinbase_unique_id & 0xffff) as u16,
            prime_id,
            // The version 3 protocol pushes the 8-byte prime id whether or not the pool runs
            // ABW (`datum_coinbaser.c` writes all eight bytes).
            wide_prime: pool.is_some_and(|p| p.protocol_v3),
            datum_active: pool.is_some(),
        })
        .map_err(BuildError::Tagging)?;
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
            pooled: set.pooled,
            subsidy_only: set.subsidy_only,
            coinbaser_id,
            coinbaser_outputs: set.included,
            pool_addr_script,
            is_datum_job: pool.is_some(),
            abw,
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

/// The subsidy-only coinbase and the pooled one, with the PoT byte at one offset in both.
/// The pooled coinbase includes every dictated output the template's room allows
/// (`coinbase::output_budget`) within the block's sigop limit: under the version 2 header
/// the mining machine never receives the coinbase, so nothing else bounds it (the C gateway
/// also built one per SHA256d-era size class, and served each miner the largest its
/// firmware took).
fn coinbase_set(
    template: &Template,
    script: &[u8],
    pot_in_script: usize,
    enprefix: u16,
    pool_script: &[u8],
    outputs: &[CoinbaseOutput],
) -> CoinbaseSet {
    let params = |outs, budget, sigops, subsidy_only| coinbase::Params {
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
        sigop_budget: sigops,
        force_op_return_extranonce: false,
    };
    let (subsidy_only, target_pot_index, _) = coinbase::build(&params(&[], 0, 0, true));
    // The transaction's bytes around the outputs: 124 of framing (the version, the input
    // with its null outpoint, scriptSig length, 15-byte extranonce push and sequence, a
    // three-byte output count, the pool output's value and script length, the 47-byte
    // witness commitment output and the lock time), the scriptSig, the pool script, and the
    // OP_RETURN output that holds the extranonce placeholder when the scriptSig has no room
    // for it (25 bytes, less the 15 the scriptSig no longer holds). The output count is one
    // byte up to 252 outputs; counted at three so the budget never exceeds the room. The C
    // gateway counts 119 and never fills the room, its size classes being far smaller.
    let fixed = 124 + pool_script.len() + script.len() + if script.len() > 85 { 10 } else { 0 };
    let budget = if outputs.is_empty() { 0 } else { coinbase::output_budget(fixed, template) };
    // The sigop cost the block has left after its transactions and the pool script's output.
    let sigops = template
        .sigoplimit
        .saturating_sub(u64::from(template.totals.sigops))
        .saturating_sub(coinbase::output_sigop_cost(pool_script));
    let (pooled, pot, included) = coinbase::build(&params(outputs, budget, sigops, false));
    debug_assert_eq!(pot, target_pot_index);
    CoinbaseSet { pooled, subsidy_only, target_pot_index, included }
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

    /// The pooled coinbase includes every dictated output the template has room for: the
    /// version 2 header sends the miner none of it, so no size class bounds the count. The
    /// room is the block's weight (four units a byte) and sigop limits less its transactions.
    #[test]
    fn the_pooled_coinbase_includes_every_dictated_output_the_block_has_room_for() {
        use crate::template::tests::{config, template};
        let pool = PoolConfig {
            payout_script: ratum::fixtures::p2wpkh(0xee),
            prime_id: 7,
            coinbase_tag: "RATUM".into(),
            min_difficulty: 1024,
            protocol_v3: false,
            abw_disabled: false,
        };
        let outputs: Vec<CoinbaseOutput> = (0..120u8)
            .map(|i| CoinbaseOutput { value: 100_000, script: ratum::fixtures::p2wpkh(i) })
            .collect();
        let build = |t: Template, outs: &[CoinbaseOutput]| {
            let split = CoinbaserResponse {
                value: t.coinbase_value,
                coinbaser_id: 1,
                outputs: outs.to_vec(),
            };
            Builder::new(Arc::new(config()))
                .build(Arc::new(t), false, Some(&pool), Some(split), None)
                .unwrap()
        };

        // Room for all 120, more than the 17 the C gateway's default class holds.
        let mut roomy = template();
        roomy.sizelimit = 4_000_000;
        roomy.weightlimit = 4_000_000;
        roomy.sigoplimit = 80_000;
        let job = build(roomy.clone(), &outputs);
        assert_eq!(job.coinbaser_outputs.len(), 120);
        let tx = job.pooled.assemble(&[0u8; EXTRANONCE_SIZE]);
        let parsed = ratum::bitcoin::parse_coinbase(&tx).unwrap();
        // The 120 dictated outputs, the remainder to the pool script, the witness commitment.
        assert_eq!(parsed.outputs.len(), 122);
        assert!(job.coinbase(coinbase::COINBASE_POOLED).is_some());

        // A block its transactions nearly fill: the coinbase shrinks to the weight left, four
        // units a byte, and the split's last outputs are left out.
        let mut tight = roomy.clone();
        let weight_used = u64::from(tight.totals.weight) + 340 + 336 + 36;
        tight.weightlimit = weight_used + 4 * 700;
        let job = build(tight, &outputs);
        let included = job.coinbaser_outputs.len();
        assert!(included > 0 && included < 120, "{included} outputs");
        let tx = job.pooled.assemble(&[0u8; EXTRANONCE_SIZE]);
        assert!(tx.len() <= 700 + 15, "the coinbase fits the room: {} bytes", tx.len());

        // The sigop limit: a legacy output costs four, a segwit output none.
        let mut legacy: Vec<CoinbaseOutput> = (0..30u8)
            .map(|i| {
                let mut s = vec![0x76, 0xa9, 0x14];
                s.extend_from_slice(&[i; 20]);
                s.extend_from_slice(&[0x88, 0xac]);
                CoinbaseOutput { value: 100_000, script: s }
            })
            .collect();
        legacy.push(CoinbaseOutput { value: 100_000, script: ratum::fixtures::p2wpkh(0xaa) });
        let mut scarce = roomy;
        scarce.sigoplimit = u64::from(scarce.totals.sigops) + 40;
        let job = build(scarce, &legacy);
        assert_eq!(job.coinbaser_outputs.len(), 11, "ten legacy outputs and the segwit one");
    }

    /// A split at the coinbaser response's limits (512 outputs of 64-byte scripts, more than
    /// its blob carries) on a block with room builds a section under the pool's limit
    /// (`MAX_COINBASE_SECTION_BYTES`, which `Verifier::resolve` refuses past), with the
    /// longest scriptSig the tags allow; a split of 512 taproot outputs, the largest a
    /// response carries whole, is included whole.
    #[test]
    fn the_pooled_coinbase_stays_under_the_pools_section_limit() {
        use crate::template::tests::{config, template};
        use ratum::datum::share::MAX_COINBASE_SECTION_BYTES;
        let pool = PoolConfig {
            payout_script: ratum::fixtures::p2wpkh(0xee),
            prime_id: 7,
            coinbase_tag: "a".repeat(80),
            min_difficulty: 1024,
            protocol_v3: true,
            abw_disabled: false,
        };
        let mut roomy = template();
        roomy.sizelimit = 4_000_000;
        roomy.weightlimit = 4_000_000;
        roomy.sigoplimit = 80_000;
        let build = |outs: Vec<CoinbaseOutput>| {
            let split =
                CoinbaserResponse { value: roomy.coinbase_value, coinbaser_id: 1, outputs: outs };
            Builder::new(Arc::new(config()))
                .build(Arc::new(roomy.clone()), false, Some(&pool), Some(split), None)
                .unwrap()
        };
        let section = |job: &Job| job.pooled.coinb1.len() + job.pooled.coinb2.len();

        let widest: Vec<CoinbaseOutput> = (0..512u16)
            .map(|i| {
                let mut s = vec![0x6a, 0x3e];
                s.extend_from_slice(&i.to_le_bytes());
                s.resize(64, 0x33);
                CoinbaseOutput { value: 1_000, script: s }
            })
            .collect();
        let job = build(widest);
        assert!(job.coinbaser_outputs.len() < 512, "{} outputs", job.coinbaser_outputs.len());
        assert!(job.coinbaser_outputs.len() > 400, "{} outputs", job.coinbaser_outputs.len());
        assert!(section(&job) <= MAX_COINBASE_SECTION_BYTES, "{} bytes", section(&job));
        assert!(section(&job) > MAX_COINBASE_SECTION_BYTES - 128, "{} bytes", section(&job));

        let taproot: Vec<CoinbaseOutput> = (0..512u16)
            .map(|i| {
                let mut s = vec![0x51, 0x20];
                s.extend_from_slice(&i.to_le_bytes());
                s.resize(34, 0x44);
                CoinbaseOutput { value: 1_000, script: s }
            })
            .collect();
        let job = build(taproot);
        assert_eq!(job.coinbaser_outputs.len(), 512);
        assert!(section(&job) <= MAX_COINBASE_SECTION_BYTES, "{} bytes", section(&job));
    }

    /// A coinbase built to the room a template leaves keeps the block under its weight limit:
    /// the header (164 bytes), the transaction count (three bytes in a block of 253 or more
    /// transactions), the coinbase with the 36-byte witness the node adds, and the
    /// transactions. Checked for every room from one output's worth to past 252 outputs, the
    /// point the output count takes three bytes, with taproot and P2WPKH splits.
    #[test]
    fn a_coinbase_built_to_the_room_keeps_the_block_under_the_weight_limit() {
        use crate::template::tests::{config, template};
        let pool = PoolConfig {
            payout_script: ratum::fixtures::p2wpkh(0xee),
            prime_id: 7,
            coinbase_tag: "RATUM".into(),
            min_difficulty: 1024,
            protocol_v3: false,
            abw_disabled: false,
        };
        let mut builder = Builder::new(Arc::new(config()));
        for (script_len, op) in [(34usize, 0x51u8), (22, 0x00)] {
            let outputs: Vec<CoinbaseOutput> = (0..512u16)
                .map(|i| {
                    let mut s = vec![op, (script_len - 2) as u8];
                    s.extend_from_slice(&i.to_le_bytes());
                    s.resize(script_len, 0x44);
                    CoinbaseOutput { value: 1_000, script: s }
                })
                .collect();
            let mut most = 0usize;
            for room in (1_000..48_000u64).step_by(7) {
                let mut t = template();
                t.sizelimit = 4_000_000;
                t.sigoplimit = 80_000;
                t.weightlimit = u64::from(t.totals.weight) + 340 + 336 + 36 + room;
                let split = CoinbaserResponse {
                    value: t.coinbase_value,
                    coinbaser_id: 1,
                    outputs: outputs.clone(),
                };
                let job = builder
                    .build(Arc::new(t.clone()), false, Some(&pool), Some(split), None)
                    .unwrap();
                let tx = job.pooled.assemble(&[0u8; EXTRANONCE_SIZE]);
                let weight = 4 * (164 + 3 + tx.len() as u64) + 36 + u64::from(t.totals.weight);
                assert!(
                    weight <= t.weightlimit,
                    "{} outputs of {script_len} bytes: block weight {weight} over {} by {}",
                    job.coinbaser_outputs.len(),
                    t.weightlimit,
                    weight - t.weightlimit
                );
                most = most.max(job.coinbaser_outputs.len());
            }
            assert!(most > 252, "{most} outputs at most: the three-byte count was not reached");
        }
    }

    #[test]
    fn sia_fields_take_both_widths() {
        assert_eq!(parse_sia_field("0100000002000000"), Some([1, 0, 0, 0, 2, 0, 0, 0]));
        assert_eq!(parse_sia_field("00000001"), Some([1, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(parse_sia_field("0001"), None);
    }
}
