//! Rebuilding the block a share claims, from the job and coinbase sections it was mined on, and
//! checking that its coinbase pays what the pool dictated and nothing else.

use super::{RebuiltShare, Verifier};
use crate::ledger::split::Payout;
use crate::payout::DictatedOutput;
use ratum::bitcoin;
use ratum::bitcoin::transaction::CoinbaseTx;
use ratum::datum::coinbase::{ParsedScriptSig, parse_script_sig};
use ratum::datum::messages::share::{self, CoinbaseSection, JobSection, PowSubmit};
use ratum::datum::messages::share_response::RejectReason;
use ratum::header::{PowHashes, XorKey};
use ratum::target;

pub(super) struct Payments {
    pub(super) paid_to_split: u64,
    pub(super) paid_to_pool: u64,
    pub(super) unpaid_outputs: Vec<Payout>,
}

impl Verifier<'_> {
    /// Rebuilds the share on `job` and `cb` against this verifier's policy, recorded splits
    /// and next target.
    pub(super) fn rebuild_share(
        &self,
        job: &JobSection,
        cb: &CoinbaseSection,
        s: &PowSubmit,
        abw_key: Option<XorKey>,
    ) -> Result<RebuiltShare, RejectReason> {
        let config = &self.policy.config;
        if s.target_byte > target::MAX_TARGET_EXPONENT
            || u64::from(s.target_byte) < u64::from(target::floor_log2(config.min_difficulty))
        {
            return Err(RejectReason::BadTarget);
        }
        let mut coinbase_tx = cb.assemble(&[0u8; share::EXTRANONCE_SIZE]);
        let parsed = bitcoin::transaction::parse_coinbase(&coinbase_tx)
            .map_err(|_| RejectReason::BadCoinbase)?;
        if parsed.has_witness {
            return Err(RejectReason::BadCoinbase);
        }

        let ParsedScriptSig { target_byte_index, tag_secondary } =
            parse_script_sig(&parsed, config.prime_id, &config.coinbase_tag)
                .ok_or(RejectReason::MissingPoolTag)?;
        if usize::from(job.target_byte_index) != target_byte_index {
            return Err(RejectReason::TargetMismatch);
        }
        // `parse_script_sig` read the index out of this transaction, so it is in bounds; this
        // is `JobSection::coinbase_tx` without assembling the transaction a second time.
        coinbase_tx[target_byte_index] = s.target_byte;

        let Payments { paid_to_split, paid_to_pool, unpaid_outputs } =
            self.check_outputs(job, &parsed, s)?;

        let merkle_root = job.merkle_root(&coinbase_tx, s.subsidy_only);
        let h = s.header(job, &merkle_root, abw_key).ok_or(RejectReason::BadCoinbase)?;

        let PowHashes { raw_pow_hash, block_hash } = h.pow_hashes();
        Ok(RebuiltShare {
            is_block: self.next_target().is_some_and(|t| target::meets_target(&block_hash, &t)),
            difficulty: s.difficulty(),
            block_hash,
            raw_pow_hash,
            prev_hash: job.prev_hash,
            job_bits: u32::from_le_bytes(job.nbits),
            header: h.serialize(),
            coinbase_tx,
            height: job.height,
            txn_count: job.txn_count,
            coinbaser_id: job.coinbaser_id,
            paid_to_split,
            paid_to_pool,
            unpaid_outputs,
            tag_secondary,
            version: s.version & !ratum::header::V2_FLAG,
            coinbase_digest: bitcoin::sha256d(
                &[&cb.coinb1[..], &cb.coinb2[..], &[u8::from(s.subsidy_only)]].concat(),
            ),
            job_generation: None,
        })
    }

    pub(super) fn check_outputs(
        &self,
        job: &JobSection,
        tx: &CoinbaseTx,
        s: &PowSubmit,
    ) -> Result<Payments, RejectReason> {
        let payout_script = &self.policy.config.payout_script;
        let recorded = if s.subsidy_only { None } else { self.splits.get(job.coinbaser_id) };
        // A split pays each identity its part of the value it was dictated for. Named by a job
        // on another parent, or by a job whose coinbase carries less than that value, its
        // outputs would pay the identities the coinbase keeps more than their part of the
        // coinbase, with the rest reaching the pool's script scaled down as owed; by a job whose
        // coinbase carries more, the difference would reach the pool's script with no owed
        // record naming it. A gateway uses a split only on the value it requested it for (the C
        // gateway compares the response's value with its request's), so the values are equal.
        if recorded.is_some_and(|d| d.prev_hash != job.prev_hash || d.value != job.coinbase_value) {
            return Err(RejectReason::BadCoinbaserId);
        }
        let dictated: &[DictatedOutput] = recorded.map_or(&[], |d| &d.outputs);

        let mut next = 0usize;
        let mut paid = vec![false; dictated.len()];
        let mut paid_to_split = 0u64;
        let mut paid_to_pool = 0u64;
        for out in &tx.outputs {
            if out.value == 0 {
                continue;
            }
            let matches = |d: &DictatedOutput| {
                d.payout.sats == out.value && d.script_pubkey == out.script_pubkey
            };
            if let Some(pos) = dictated[next..].iter().position(matches) {
                paid_to_split = paid_to_split.saturating_add(out.value);
                paid[next + pos] = true;
                next += pos + 1;
                continue;
            }
            if out.script_pubkey == *payout_script {
                paid_to_pool = paid_to_pool.saturating_add(out.value);
                continue;
            }
            return Err(RejectReason::BadCoinbaseOutputs);
        }

        if !s.subsidy_only && paid_to_split.saturating_add(paid_to_pool) != job.coinbase_value {
            return Err(RejectReason::BadCoinbase);
        }

        let unpaid_outputs = dictated
            .iter()
            .zip(paid)
            .filter(|(d, paid)| !paid && d.script_pubkey != *payout_script)
            .map(|(d, _)| d.payout.clone())
            .collect();

        Ok(Payments { paid_to_split, paid_to_pool, unpaid_outputs })
    }
}
