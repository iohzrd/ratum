use crate::coinbase::{self, Coinbase};
use crate::config::Config;
use crate::template::Template;
use ratum::bitcoin::HASH_SIZE;
use ratum::datum::messages::{CoinbaseOutput, CoinbaserResponse};
use ratum::datum::share::{EXTRANONCE_SIZE, EXTRANONCE_SIZE_V2, SIA_FIELD_HALF};
use ratum::header::{self, HeaderV2};
use ratum::target::{self, Target};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub use ratum::datum::share::{
    COINBASE_ID_SUBSIDY_ONLY as COINBASE_SUBSIDY_ONLY, MAX_JOBS, SIA_FIELD_SIZE,
};
pub const JOB_INDEX_XOR: u16 = 0xC0DE;
const ENPREFIX_XOR: u16 = 0xB10C;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolConfig {
    pub payout_script: Vec<u8>,
    pub prime_id: u64,
    pub coinbase_tag: String,
    pub min_difficulty: u64,
    pub protocol_v3: bool,
    pub abw_disabled: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Abw {
    pub slot: u8,
    pub key_hash: [u8; 32],
}

pub struct Job {
    pub serial: u64,
    pub global_index: u8,
    pub job_id: String,
    pub datum_slot: u8,
    pub template: Arc<Template>,
    pub ntime_hex: String,
    pub block_target: Target,
    pub prevblock_hidden: [u8; 32],
    pub merkle_branches: Vec<[u8; 32]>,
    pub target_pot_index: usize,
    pub pooled: Coinbase,
    pub subsidy_only: Coinbase,
    pub coinbaser_id: u8,
    pub coinbaser_outputs: Vec<CoinbaseOutput>,
    pub pool_addr_script: Vec<u8>,
    pub is_datum_job: bool,
    pub abw: Option<Abw>,
    pub is_new_block: bool,
    pub created: Instant,
    pub stale_prevblock: AtomicBool,
    commitments: Mutex<HashMap<(u8, u8), Commitment>>,
}

#[derive(Clone, Debug)]
pub struct Commitment {
    pub merkle_root: [u8; 32],
    pub h2: [u8; 32],
    pub txcount: u16,
}

pub struct PayoutRow {
    pub value: u64,
    pub script: Vec<u8>,
    pub remainder: bool,
}

impl Job {
    pub fn coinbase(&self, id: u8) -> &Coinbase {
        if id == COINBASE_SUBSIDY_ONLY { &self.subsidy_only } else { &self.pooled }
    }

    pub fn is_stale_prevblock(&self) -> bool {
        self.stale_prevblock.load(Ordering::Relaxed)
    }

    pub fn full_coinbase(&self, id: u8, pot: u8) -> Option<Vec<u8>> {
        let mut tx = self.coinbase(id).assemble(&[0u8; EXTRANONCE_SIZE]);
        *tx.get_mut(self.target_pot_index)? = pot;
        Some(tx)
    }

    fn header_base(&self, merkle_root: [u8; 32], txcount: u16, pot: u8) -> HeaderV2 {
        HeaderV2 {
            version: self.template.version as i32,
            prev_block: self.template.prev_hash,
            merkle_root,
            time: self.template.curtime as u32,
            bits: self.template.nbits,
            txcount,
            height: self.template.height as i32,
            xor_key_mask_clear_bits: self.abw.map_or(0, |_| ratum::datum::abw::clear_bits(pot)),
            ..Default::default()
        }
    }

    fn header_h2(&self, h: &HeaderV2) -> [u8; 32] {
        match self.abw {
            Some(a) => h.precompute_with_key_hash(a.key_hash).h2,
            None => h.precompute().h2,
        }
    }

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

    pub fn header(
        &self,
        id: u8,
        pot: u8,
        extranonce: [u8; EXTRANONCE_SIZE_V2],
        sia_nonce: [u8; SIA_FIELD_SIZE],
        sia_ntime: [u8; SIA_FIELD_SIZE],
    ) -> Option<HeaderV2> {
        let halves = |f: [u8; SIA_FIELD_SIZE]| {
            let (lo, hi) = f.split_at(SIA_FIELD_HALF);
            (u32::from_le_bytes(lo.try_into().unwrap()), u32::from_le_bytes(hi.try_into().unwrap()))
        };
        let c = self.commitment(id, pot)?;
        let mut h = self.header_base(c.merkle_root, c.txcount, pot);
        h.extranonce = extranonce;
        (h.nonce, h.nonce2) = halves(sia_nonce);
        (h.time_offset, h.nonce3) = halves(sia_ntime);
        Some(h)
    }

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

pub fn merkle_branches(txids: &[[u8; 32]]) -> Vec<[u8; 32]> {
    if txids.is_empty() {
        return Vec::new();
    }
    let mut level: Vec<Option<[u8; 32]>> = Vec::with_capacity(txids.len() + 1);
    level.push(None);
    level.extend(txids.iter().map(|t| Some(*t)));
    let mut branches = Vec::new();
    let mut combined = [0u8; 2 * HASH_SIZE];
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
                    combined[..HASH_SIZE].copy_from_slice(&a);
                    combined[HASH_SIZE..].copy_from_slice(&b);
                    next.push(Some(ratum::bitcoin::sha256d(&combined)));
                }
                _ => next.push(None),
            }
        }
        level = next;
    }
    branches
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BuildError {
    #[error("pool payout script of {0} bytes")]
    PayoutScriptSize(usize),
    #[error("{0}")]
    Tagging(String),
    #[error("{0} merkle branches; the protocol carries at most {max}",
            max = ratum::datum::share::MAX_MERKLE_BRANCHES)]
    TooManyBranches(usize),
    #[error("the template's bits do not decode")]
    BadBits,
}

struct CoinbaseSet {
    pooled: Coinbase,
    subsidy_only: Coinbase,
    target_pot_index: usize,
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
        let enprefix = self.enprefix ^ ENPREFIX_XOR;
        self.enprefix = self.enprefix.wrapping_add(1);
        let slots = c.datum.protocol_job_slots as u32;
        let datum_slot = self.datum_slot;
        self.datum_slot = ((u32::from(self.datum_slot) + 1) % slots) as u8;

        let (pool_addr_script, prime_id, tag_primary) = match pool {
            Some(p) => (p.payout_script.clone(), p.prime_id, p.coinbase_tag.as_str()),
            None => (c.pool_output_script.clone(), 0, c.mining.coinbase_tag_primary.as_str()),
        };
        if pool_addr_script.is_empty()
            || pool_addr_script.len() > ratum::datum::messages::MAX_OUTPUT_SCRIPT
        {
            return Err(BuildError::PayoutScriptSize(pool_addr_script.len()));
        }
        let (script, pot_in_script) = coinbase::script_sig(&coinbase::Tagging {
            height: template.height,
            tag_primary,
            tag_secondary: &c.mining.coinbase_tag_secondary,
            unique_id: (c.mining.coinbase_unique_id & u32::from(u16::MAX)) as u16,
            prime_id,
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
        let now = ratum::unix_now() as u32;
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
    let fixed =
        coinbase::fixed_bytes(script.len(), pool_script.len(), template.witness_commitment.len());
    let budget = if outputs.is_empty() { 0 } else { coinbase::output_budget(fixed, template) };
    let sigops = template
        .sigoplimit
        .saturating_sub(u64::from(template.totals.sigops))
        .saturating_sub(coinbase::output_sigop_cost(pool_script));
    let (pooled, pot, included) = coinbase::build(&params(outputs, budget, sigops, false));
    debug_assert_eq!(pot, target_pot_index);
    CoinbaseSet { pooled, subsidy_only, target_pot_index, included }
}

pub const JOB_ID_TIME_CHARS: usize = 8;
const JOB_ID_CHARS: usize = 14;
const JOB_ID_INDEX_AT: std::ops::Range<usize> = 10..JOB_ID_CHARS;
const NOTIFY_ID_CHARS: usize = JOB_ID_CHARS + 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobRef {
    pub global_index: u8,
    pub quickdiff: bool,
    pub empty: bool,
    pub coinbase: u8,
}

const QUICKDIFF_PREFIX: char = 'Q';
const EMPTY_PREFIX: char = 'N';

impl JobRef {
    pub fn notify_id(&self, job: &Job) -> String {
        let cb = self.coinbase;
        if self.quickdiff {
            format!("{QUICKDIFF_PREFIX}{}{cb:02x}", job.job_id)
        } else if self.empty {
            format!("{EMPTY_PREFIX}{}{COINBASE_SUBSIDY_ONLY:02x}", job.job_id)
        } else {
            format!("{}{cb:02x}", job.job_id)
        }
    }

    pub fn parse(s: &str) -> Option<(JobRef, &str)> {
        const PREFIXED: usize = NOTIFY_ID_CHARS + 1;
        let (quickdiff, empty, rest) = match s.len() {
            NOTIFY_ID_CHARS => (false, false, s),
            PREFIXED if s.starts_with(QUICKDIFF_PREFIX) => (true, false, &s[1..]),
            PREFIXED if s.starts_with(EMPTY_PREFIX) => (false, true, &s[1..]),
            _ => return None,
        };
        let job_id = rest.get(..JOB_ID_CHARS)?;
        let global_index = global_index_of(job_id)?;
        let coinbase = u8::from_str_radix(rest.get(JOB_ID_CHARS..NOTIFY_ID_CHARS)?, 16).ok()?;
        if empty && coinbase != COINBASE_SUBSIDY_ONLY {
            return None;
        }
        Some((JobRef { global_index, quickdiff, empty, coinbase }, job_id))
    }
}

pub fn global_index_of(job_id: &str) -> Option<u8> {
    let raw = u16::from_str_radix(job_id.get(JOB_ID_INDEX_AT)?, 16).ok()?;
    let idx = raw ^ JOB_INDEX_XOR;
    if idx as usize >= MAX_JOBS { None } else { Some(idx as u8) }
}

pub fn parse_sia_field(s: &str) -> Option<[u8; SIA_FIELD_SIZE]> {
    const HEX_CHARS: usize = 2 * SIA_FIELD_SIZE;
    const NARROW_HEX_CHARS: usize = 2 * SIA_FIELD_HALF;
    match s.len() {
        HEX_CHARS => hex::decode(s).ok()?.try_into().ok(),
        NARROW_HEX_CHARS => {
            let v = u32::from_str_radix(s, 16).ok()?;
            let mut out = [0u8; SIA_FIELD_SIZE];
            out[..SIA_FIELD_HALF].copy_from_slice(&v.to_le_bytes());
            Some(out)
        }
        _ => None,
    }
}
