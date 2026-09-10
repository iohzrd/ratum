use super::{PoolPolicy, RebuiltShare, Splits};
use ratum::bitcoin::{self, CoinbaseTx};
use ratum::datum::abw::XorKey;
use ratum::datum::coinbase::{
    TAG_END, TAG_SEPARATOR, UID_PUSH_PREFIX_SIZE, UID_PUSH_SIZE_V1, UID_PUSH_SIZE_V3,
};
use ratum::datum::messages::{CoinbaseOutput, RejectReason};
use ratum::datum::share::{self, CoinbaseSection, JobSection, PowSubmit};
use ratum::header::{self, HeaderV2};
use ratum::target;

pub(super) fn build_work(
    policy: &PoolPolicy,
    splits: &Splits,
    job: &JobSection,
    cb: &CoinbaseSection,
    s: &PowSubmit,
    abw_key: Option<XorKey>,
) -> Result<RebuiltShare, RejectReason> {
    if s.target_byte > target::MAX_TARGET_POT
        || u64::from(s.target_byte) < u64::from(target::floor_pot(policy.min_difficulty))
    {
        return Err(RejectReason::BadTarget);
    }
    let mut coinbase_tx = cb.assemble(&[0u8; share::EXTRANONCE_SIZE]);

    let parsed = bitcoin::parse_coinbase(&coinbase_tx).map_err(|_| RejectReason::BadCoinbase)?;
    if parsed.has_witness {
        return Err(RejectReason::BadCoinbase);
    }

    let (pot_index, tag_secondary) = locate_pot_byte(&parsed, policy)?;
    if usize::from(s.target_byte_index_of(job)) != pot_index {
        return Err(RejectReason::TargetMismatch);
    }
    coinbase_tx[pot_index] = s.target_byte;

    let Payments { to_split: paid_to_split, to_pool: paid_to_pool, unpaid } =
        check_outputs(policy, splits, job, &parsed, s)?;

    let branches: &[[u8; 32]] = if s.subsidy_only { &[] } else { job.merkle_branches.as_slice() };
    let merkle_root = bitcoin::merkle_root(&bitcoin::sha256d(&coinbase_tx), branches);

    let h = build_header_v2(job, s, &s.blake2b, &merkle_root, abw_key)?;

    let (raw_hash, block_hash) = h.pow_and_block_hash();
    Ok(RebuiltShare {
        difficulty: s.difficulty(),
        block_hash,
        raw_hash,
        prev_hash: job.prev_hash,
        job_bits: u32::from_le_bytes(job.nbits),
        header: h.serialize(),
        coinbase_tx,
        height: job.height,
        txn_count: job.txn_count,
        coinbaser_id: job.coinbaser_id,
        paid_to_split,
        paid_to_pool,
        unpaid,
        tag_secondary,
    })
}

pub(super) fn build_header_v2(
    job: &JobSection,
    s: &PowSubmit,
    b: &share::Blake2bSection,
    merkle_root: &[u8; 32],
    abw_key: Option<XorKey>,
) -> Result<HeaderV2, RejectReason> {
    let (nonce, nonce2) = b.nonce_fields();
    let (time_offset, nonce3) = b.time_fields();
    let extranonce =
        share::header_extranonce(&s.extranonce).ok_or(RejectReason::BadExtranonceSize)?;
    let tx_count = if s.subsidy_only { 1 } else { u64::from(job.txn_count) + 1 };
    let txcount = u16::try_from(tx_count).map_err(|_| RejectReason::BadCoinbase)?;

    let mut h = HeaderV2 {
        version: (s.version & !header::V2_FLAG) as i32,
        prev_block: job.prev_hash,
        merkle_root: *merkle_root,
        time: b.time_on_wire,
        bits: u32::from_le_bytes(job.nbits),
        nonce,
        nonce2,
        nonce3,
        extranonce,
        time_offset,
        txcount,
        flags: if s.use_time_offset { header::FLAG_USE_TIME_OFFSET } else { 0 },
        xor_key_mask_clear_bits: abw_key
            .map_or(0, |_| ratum::datum::abw::clear_bits(s.target_byte)),
        xor_key: abw_key.unwrap_or([0u8; 16]),
        height: job.height as i32,
        mm_rhs: [0u8; 32],
    };
    if s.use_time_offset {
        h.time = b.time_on_wire.wrapping_add(time_offset);
    }
    Ok(h)
}

pub(super) fn locate_pot_byte(
    tx: &CoinbaseTx,
    policy: &PoolPolicy,
) -> Result<(usize, String), RejectReason> {
    let pushes = bitcoin::script_pushes(&tx.script_sig);
    let prime = policy.prime_id.to_le_bytes();
    let uid_push = pushes
        .iter()
        .position(|(_, data)| {
            let Some(id) = data.get(UID_PUSH_PREFIX_SIZE..) else { return false };
            match data.len() {
                UID_PUSH_SIZE_V1 => {
                    u32::try_from(policy.prime_id).is_ok() && id == &prime[..size_of::<u32>()]
                }
                UID_PUSH_SIZE_V3 => id == prime,
                _ => false,
            }
        })
        .ok_or(RejectReason::MissingPoolTag)?;

    let mut tag_secondary = String::new();
    let tag_push = uid_push.checked_sub(1).map(|i| pushes[i].1);
    if !policy.coinbase_tag.is_empty() {
        let tag = policy.coinbase_tag.as_bytes();
        let (marker, rest) = tag_push
            .and_then(|data| data.strip_prefix(tag))
            .and_then(|after| after.split_first())
            .filter(|(marker, _)| matches!(**marker, TAG_END | TAG_SEPARATOR))
            .ok_or(RejectReason::MissingPoolTag)?;
        if *marker == TAG_SEPARATOR {
            tag_secondary = decode_tag(rest);
        }
    } else if let Some(rest) = tag_push.and_then(|data| data.strip_prefix(&[TAG_SEPARATOR])) {
        tag_secondary = decode_tag(rest);
    }

    Ok((tx.script_sig_offset + pushes[uid_push].0, tag_secondary))
}

pub(super) fn decode_tag(bytes: &[u8]) -> String {
    let bytes = bytes.strip_suffix(&[TAG_END]).unwrap_or(bytes);
    String::from_utf8_lossy(bytes).chars().filter(|c| !c.is_control()).collect()
}

pub(super) struct Payments {
    pub(super) to_split: u64,
    pub(super) to_pool: u64,
    pub(super) unpaid: Vec<usize>,
}

pub(super) fn check_outputs(
    policy: &PoolPolicy,
    splits: &Splits,
    job: &JobSection,
    tx: &CoinbaseTx,
    s: &PowSubmit,
) -> Result<Payments, RejectReason> {
    let recorded = if s.subsidy_only { None } else { splits.get(&job.coinbaser_id) };
    let empty: Vec<CoinbaseOutput> = Vec::new();
    let dictated = recorded.map_or(&empty, |d| &d.outputs);

    let mut next = 0usize;
    let mut paid = vec![false; dictated.len()];
    let mut paid_to_split = 0u64;
    let mut paid_to_pool = 0u64;
    for out in &tx.outputs {
        if out.value == 0 {
            continue;
        }
        if let Some(pos) =
            dictated[next..].iter().position(|d| d.value == out.value && d.script == out.script)
        {
            paid_to_split = paid_to_split.saturating_add(out.value);
            paid[next + pos] = true;
            next += pos + 1;
            continue;
        }
        if out.script == policy.payout_script {
            paid_to_pool = paid_to_pool.saturating_add(out.value);
            continue;
        }
        return Err(RejectReason::BadCoinbaseOutputs);
    }

    if !s.subsidy_only && paid_to_split.saturating_add(paid_to_pool) != job.coinbase_value {
        return Err(RejectReason::BadCoinbase);
    }

    let unpaid = dictated
        .iter()
        .enumerate()
        .filter(|(i, d)| !paid[*i] && d.script != policy.payout_script)
        .map(|(i, _)| i)
        .collect();

    Ok(Payments { to_split: paid_to_split, to_pool: paid_to_pool, unpaid })
}
