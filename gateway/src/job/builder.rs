//! Building a job from a template, the pool's configuration and the split it dictated: the
//! scriptSig, the two coinbases, and the job section a share carries to the pool.

use super::{CoinbaseKind, Job};
use crate::config::Config;
use crate::datum::abw::AbwAssignment;
use crate::stratum::notify_id::stratum_job_id;
use crate::template::Template;
use log::warn;
use ratum::bitcoin::merkle_branches;
use ratum::bitcoin::script::output_script_size_is_valid;
use ratum::bitcoin::transaction::TxOut;
use ratum::datum::coinbase::{self, BlockLimits, BuiltCoinbase, CoinbaseSpec, ScriptSigInputs};
use ratum::datum::messages::coinbaser::CoinbaserResponse;
use ratum::datum::messages::config::{ClientConfig, MAX_PAYOUT_SCRIPT_LEN};
use ratum::datum::messages::share::{JobSection, MAX_MERKLE_BRANCHES};
use ratum::{header, target};
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Instant;

const ENPREFIX_XOR: u16 = 0xB10C;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BuildError {
    #[error("pool payout script of {0} bytes")]
    PayoutScriptSize(usize),
    #[error("the coinbase tags do not fit the scriptSig")]
    TagsDoNotFit,
    #[error("{0} merkle branches; the protocol carries at most {max}",
            max = MAX_MERKLE_BRANCHES)]
    TooManyBranches(usize),
    #[error("the template's bits do not decode")]
    BadBits,
}

/// What a job is built from besides the gateway's own configuration: the pool's configuration
/// and the split it dictated are absent for non-pooled work, and the assignment for work under
/// no anti-block-withholding commitment.
pub struct JobInputs<'a> {
    pub serial: u64,
    pub template: Arc<Template>,
    pub pool_config: Option<&'a ClientConfig>,
    pub coinbaser: Option<CoinbaserResponse>,
    pub abw: Option<AbwAssignment>,
}

impl JobInputs<'_> {
    /// The inputs for job `serial` on `template`, with no pool configuration, split or
    /// assignment.
    pub fn new(serial: u64, template: Arc<Template>) -> Self {
        Self { serial, template, pool_config: None, coinbaser: None, abw: None }
    }
}

/// Builds the job numbered `j.serial`; its slot and extranonce prefix are each derived from
/// the serial. One job carries both coinbases, so which of them the work commits to is
/// decided when it is published, not here.
pub fn build(c: &Config, j: JobInputs<'_>) -> Result<Job, BuildError> {
    let JobInputs { serial, template, pool_config, coinbaser, abw } = j;
    let slot = (serial % c.datum.protocol_job_slots as u64) as u8;
    let enprefix = (serial as u16) ^ ENPREFIX_XOR;

    let pool_payout_script = c.payout_script(pool_config).to_vec();
    let (prime_id, tag_primary) = match pool_config {
        Some(p) => (p.prime_id, p.coinbase_tag.as_str()),
        None => (0, c.mining.coinbase_tag_primary.as_str()),
    };
    if pool_payout_script.is_empty() || pool_payout_script.len() > MAX_PAYOUT_SCRIPT_LEN {
        return Err(BuildError::PayoutScriptSize(pool_payout_script.len()));
    }
    let (script, target_byte_index_in_script) = coinbase::script_sig(&ScriptSigInputs {
        height: template.height,
        tag_primary,
        tag_secondary: &c.mining.coinbase_tag_secondary,
        // `validate_mining` holds this inside COINBASE_UNIQUE_ID_RANGE, so the cast keeps it.
        unique_id: c.mining.coinbase_unique_id as u16,
        prime_id,
        wide_prime: pool_config.is_some_and(|p| p.v3.is_some()),
        datum_active: pool_config.is_some(),
    })
    .ok_or(BuildError::TagsDoNotFit)?;
    let split = filter_coinbaser(&template, coinbaser);
    let (pooled_coinbase, subsidy_only_coinbase, coinbaser_outputs) = build_coinbases(
        &template,
        &script,
        target_byte_index_in_script,
        enprefix,
        &pool_payout_script,
        &split.outputs,
    );

    let txids: Vec<[u8; 32]> = template.txns.iter().map(|t| t.txid).collect();
    let merkle_branches = merkle_branches(&txids);
    if merkle_branches.len() > MAX_MERKLE_BRANCHES {
        return Err(BuildError::TooManyBranches(merkle_branches.len()));
    }
    let job_section = JobSection {
        prev_hash: template.prev_hash,
        target_byte_index: pooled_coinbase.target_byte_index as u16,
        nbits: template.nbits.to_le_bytes(),
        coinbaser_id: split.coinbaser_id,
        height: template.height,
        coinbase_value: template.coinbase_value,
        txn_count: template.txns.len() as u32,
        txn_total_weight: template.totals.weight,
        txn_total_size: template.totals.size,
        txn_total_sigops: template.totals.sigops,
        merkle_branches,
    };
    Ok(Job {
        serial,
        slot,
        stratum_job_id: stratum_job_id(ratum::unix_now() as u32, slot),
        block_target: target::bits_to_target(template.nbits).ok_or(BuildError::BadBits)?,
        prevblock_hidden: header::prevblock_hidden(&template.prev_hash),
        job_section,
        pooled_coinbase,
        subsidy_only_coinbase,
        coinbaser_outputs,
        pool_payout_script,
        is_datum_job: pool_config.is_some(),
        abw,
        created_at: Instant::now(),
        stale_prevblock: AtomicBool::new(false),
        commitments: Mutex::new(HashMap::new()),
        template,
    })
}

/// The split with the outputs the template's rules refuse removed; no split is id 0 with
/// no outputs.
fn filter_coinbaser(
    template: &Template,
    coinbaser: Option<CoinbaserResponse>,
) -> CoinbaserResponse {
    let Some(r) = coinbaser else {
        return CoinbaserResponse {
            value: template.coinbase_value,
            coinbaser_id: 0,
            outputs: Vec::new(),
        };
    };
    let (kept, dropped): (Vec<_>, Vec<_>) = r
        .outputs
        .into_iter()
        .partition(|o| !template.reduced_data || output_script_size_is_valid(&o.script_pubkey));
    for o in dropped {
        warn!(
            "Coinbaser sent a {} byte output script, over the reduced_data limit for block {}. Leaving that output out of the generation txn.",
            o.script_pubkey.len(),
            template.height
        );
    }
    CoinbaserResponse { outputs: kept, ..r }
}

fn build_coinbases(
    template: &Template,
    script: &[u8],
    target_byte_index_in_script: usize,
    enprefix: u16,
    pool_payout_script: &[u8],
    outputs: &[TxOut],
) -> (BuiltCoinbase, BuiltCoinbase, Vec<TxOut>) {
    let limits = BlockLimits {
        sizelimit: template.sizelimit,
        weightlimit: template.weightlimit,
        txn_total_size: u64::from(template.totals.size),
        txn_total_weight: u64::from(template.totals.weight),
    };
    let spec = |outs, sigops, kind: CoinbaseKind| CoinbaseSpec {
        coinbase_id: kind.wire_id(),
        script_sig: script,
        target_byte_index_in_script,
        enprefix,
        witness_commitment: match kind {
            CoinbaseKind::Pooled => Some(&template.witness_commitment),
            CoinbaseKind::SubsidyOnly => None,
        },
        pool_payout_script,
        coinbase_value: match kind {
            CoinbaseKind::Pooled => template.coinbase_value,
            CoinbaseKind::SubsidyOnly => template.coinbase_value - template.totals.fee,
        },
        outputs: outs,
        limits,
        sigop_budget: sigops,
    };
    let (subsidy_only, _) = coinbase::build(&spec(&[], 0, CoinbaseKind::SubsidyOnly));
    let sigops = template
        .sigoplimit
        .saturating_sub(u64::from(template.totals.sigops))
        .saturating_sub(coinbase::output_sigop_cost(pool_payout_script));
    let (pooled, included_outputs) = coinbase::build(&spec(outputs, sigops, CoinbaseKind::Pooled));
    debug_assert_eq!(pooled.target_byte_index, subsidy_only.target_byte_index);
    (pooled, subsidy_only, included_outputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{config, template};
    use ratum::bitcoin::transaction::parse_coinbase;
    use ratum::datum::handshake::RESUME_TOKEN_LEN;
    use ratum::datum::messages::config::V3Config;
    use ratum::datum::messages::share::EXTRANONCE_SIZE;
    use ratum::fixtures::{p2pkh, p2wpkh};

    #[test]
    fn the_pooled_coinbase_includes_every_dictated_output_the_block_has_room_for() {
        let pool = ClientConfig {
            payout_script: p2wpkh(0xee),
            prime_id: 7,
            coinbase_tag: "RATUM".into(),
            min_difficulty: 1024,
            v3: None,
        };
        let outputs: Vec<TxOut> =
            (0..120u8).map(|i| TxOut { value: 100_000, script_pubkey: p2wpkh(i) }).collect();
        let build = |t: Template, outs: &[TxOut]| {
            let split = CoinbaserResponse {
                value: t.coinbase_value,
                coinbaser_id: 1,
                outputs: outs.to_vec(),
            };
            build(
                &config(),
                JobInputs {
                    pool_config: Some(&pool),
                    coinbaser: Some(split),
                    ..JobInputs::new(0, Arc::new(t))
                },
            )
            .unwrap()
        };

        let mut roomy = template();
        roomy.sizelimit = 4_000_000;
        roomy.weightlimit = 4_000_000;
        roomy.sigoplimit = 80_000;
        let job = build(roomy.clone(), &outputs);
        assert_eq!(job.coinbaser_outputs.len(), 120);
        let tx = job.pooled_coinbase.section.assemble(&[0u8; EXTRANONCE_SIZE]);
        let parsed = parse_coinbase(&tx).unwrap();
        assert_eq!(parsed.outputs.len(), 122);
        assert_eq!(job.coinbase(CoinbaseKind::Pooled), &job.pooled_coinbase);

        let mut tight = roomy.clone();
        let weight_used = u64::from(tight.totals.weight) + 340 + 336 + 36;
        tight.weightlimit = weight_used + 4 * 700;
        let job = build(tight, &outputs);
        let included = job.coinbaser_outputs.len();
        assert!(included > 0 && included < 120, "{included} outputs");
        let tx = job.pooled_coinbase.section.assemble(&[0u8; EXTRANONCE_SIZE]);
        assert!(tx.len() <= 700 + 15, "the coinbase fits the room: {} bytes", tx.len());

        let mut legacy: Vec<TxOut> =
            (0..30u8).map(|i| TxOut { value: 100_000, script_pubkey: p2pkh(i) }).collect();
        legacy.push(TxOut { value: 100_000, script_pubkey: p2wpkh(0xaa) });
        let mut scarce = roomy;
        scarce.sigoplimit = u64::from(scarce.totals.sigops) + 40;
        let job = build(scarce, &legacy);
        assert_eq!(job.coinbaser_outputs.len(), 11, "ten legacy outputs and the segwit one");
    }

    #[test]
    fn the_pooled_coinbase_stays_under_the_pools_section_limit() {
        use ratum::datum::messages::share::MAX_COINBASE_SECTION_LEN;
        let pool = ClientConfig {
            payout_script: p2wpkh(0xee),
            prime_id: 7,
            coinbase_tag: "a".repeat(80),
            min_difficulty: 1024,
            v3: Some(V3Config {
                resume_token: [0u8; RESUME_TOKEN_LEN],
                bulk_framing: false,
                abw_disabled: false,
            }),
        };
        let mut roomy = template();
        roomy.sizelimit = 4_000_000;
        roomy.weightlimit = 4_000_000;
        roomy.sigoplimit = 80_000;
        let build = |outs: Vec<TxOut>| {
            let split =
                CoinbaserResponse { value: roomy.coinbase_value, coinbaser_id: 1, outputs: outs };
            build(
                &config(),
                JobInputs {
                    pool_config: Some(&pool),
                    coinbaser: Some(split),
                    ..JobInputs::new(0, Arc::new(roomy.clone()))
                },
            )
            .unwrap()
        };
        let section = |job: &Job| {
            job.pooled_coinbase.section.coinb1.len() + job.pooled_coinbase.section.coinb2.len()
        };

        let widest: Vec<TxOut> = (0..512u16)
            .map(|i| {
                let mut s = vec![0x6a, 0x3e];
                s.extend_from_slice(&i.to_le_bytes());
                s.resize(64, 0x33);
                TxOut { value: 1_000, script_pubkey: s }
            })
            .collect();
        let job = build(widest);
        assert!(job.coinbaser_outputs.len() < 512, "{} outputs", job.coinbaser_outputs.len());
        assert!(job.coinbaser_outputs.len() > 400, "{} outputs", job.coinbaser_outputs.len());
        assert!(section(&job) <= MAX_COINBASE_SECTION_LEN, "{} bytes", section(&job));
        assert!(section(&job) > MAX_COINBASE_SECTION_LEN - 128, "{} bytes", section(&job));

        let taproot: Vec<TxOut> = (0..512u16)
            .map(|i| {
                let mut s = vec![0x51, 0x20];
                s.extend_from_slice(&i.to_le_bytes());
                s.resize(34, 0x44);
                TxOut { value: 1_000, script_pubkey: s }
            })
            .collect();
        let job = build(taproot);
        assert_eq!(job.coinbaser_outputs.len(), 512);
        assert!(section(&job) <= MAX_COINBASE_SECTION_LEN, "{} bytes", section(&job));
    }

    #[test]
    fn a_coinbase_built_to_the_room_keeps_the_block_under_the_weight_limit() {
        let pool = ClientConfig {
            payout_script: p2wpkh(0xee),
            prime_id: 7,
            coinbase_tag: "RATUM".into(),
            min_difficulty: 1024,
            v3: None,
        };
        let config = config();
        for (script_len, op) in [(34usize, 0x51u8), (22, 0x00)] {
            let outputs: Vec<TxOut> = (0..512u16)
                .map(|i| {
                    let mut s = vec![op, (script_len - 2) as u8];
                    s.extend_from_slice(&i.to_le_bytes());
                    s.resize(script_len, 0x44);
                    TxOut { value: 1_000, script_pubkey: s }
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
                let job = build(
                    &config,
                    JobInputs {
                        pool_config: Some(&pool),
                        coinbaser: Some(split),
                        ..JobInputs::new(0, Arc::new(t.clone()))
                    },
                )
                .unwrap();
                let tx = job.pooled_coinbase.section.assemble(&[0u8; EXTRANONCE_SIZE]);
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
}
