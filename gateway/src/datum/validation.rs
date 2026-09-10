use super::{Pool, Settings};
use crate::job::Job;
use log::{info, warn};
use ratum::datum::handshake::KeyPairs;
use ratum::datum::validation::{
    self, ParentFetchReply, ParentStatus, ShortTxnList, Status, TxnBundle,
};
use std::sync::Arc;

pub(super) fn response_to(
    pool: &Pool,
    settings: &Settings,
    identity: &KeyPairs,
    plain: &[u8],
) -> Option<Vec<u8>> {
    let sub = *plain.get(validation::SELECTOR_AT)?;
    let job_index = plain.get(validation::JOB_INDEX_AT).copied();
    let lookup = job_index
        .ok_or((validation::JOB_INDEX_INVALID, Status::BadRequest))
        .and_then(|i| pool.slot(i));
    let response = match sub {
        validation::request::SHORT_TXN_LIST => {
            info!("pool requested the short transaction list of job {job_index:?}");
            match lookup {
                Ok(job) => short_txn_list(settings, identity, &job),
                Err((idx, status)) => ShortTxnList::empty(idx, status),
            }
            .encode()
        }
        validation::request::TXNS | validation::request::BLOCK_TXNS => {
            let all = sub == validation::request::BLOCK_TXNS;
            let bundle = txn_bundle(lookup, plain, all);
            info!(
                "pool requested {} of job {job_index:?}: sending {}",
                if all { "the block transactions" } else { "transactions" },
                bundle.txns.len()
            );
            bundle.encode()
        }
        validation::request::PARENT_FETCH => {
            if plain.len() != validation::PARENT_FETCH_REQUEST_LEN {
                warn!("malformed parent fetch request ({} bytes)", plain.len());
                return None;
            }
            let idx = plain[validation::JOB_INDEX_AT];
            let parent_hash: [u8; 32] =
                plain[validation::REQUEST_HEADER_LEN..].try_into().expect("32 bytes");
            let (status, block) = match lookup {
                Ok(job) if job.template.prev_hash == parent_hash => {
                    fetch_parent(pool, &job.template.prev_hash_hex)
                }
                _ => (ParentStatus::JobMismatch, Vec::new()),
            };
            info!(
                "pool requested the parent block of job {idx}: {status:?}, {} bytes",
                block.len()
            );
            ParentFetchReply { job_index: idx, status, parent_hash, block }.encode()
        }
        other => {
            warn!("unknown validation request {other:#04x}");
            return None;
        }
    };
    Some(response)
}

fn fetch_parent(pool: &Pool, hash_hex: &str) -> (ParentStatus, Vec<u8>) {
    let Some(node) = &pool.node else { return (ParentStatus::Unavailable, Vec::new()) };
    match node.call("getblock", serde_json::json!([hash_hex, 0])) {
        Ok(serde_json::Value::String(hex)) => match hex::decode(&hex) {
            Ok(block) if !block.is_empty() && block.len() <= validation::MAX_PARENT_FETCH_BLOCK => {
                (ParentStatus::Success, block)
            }
            _ => (ParentStatus::RpcFailed, Vec::new()),
        },
        Ok(_) => (ParentStatus::RpcFailed, Vec::new()),
        Err(e) => {
            warn!("getblock for the parent fetch failed: {e}");
            (ParentStatus::Unavailable, Vec::new())
        }
    }
}

fn short_txn_list(settings: &Settings, identity: &KeyPairs, job: &Job) -> ShortTxnList {
    let hashes = job.template.witness_hashes();
    if hashes.len() > validation::MAX_SHORT_LIST_TXNS as usize {
        return ShortTxnList::empty(job.datum_slot, Status::TooManyTxns);
    }
    let key = validation::short_id_key(&identity.sign_pk, &settings.pool_sign_pk);
    ShortTxnList {
        job_index: job.datum_slot,
        status: Status::Ok,
        txn_count: hashes.len() as u16,
        short_ids: hashes.iter().map(|h| validation::short_id(h, &key)).collect(),
        crosscheck: if hashes.is_empty() { None } else { Some(validation::crosscheck(&hashes)) },
    }
}

fn txn_bundle(lookup: Result<Arc<Job>, (u8, Status)>, plain: &[u8], all: bool) -> TxnBundle {
    let selector = if all { validation::response::BLOCK_TXNS } else { validation::response::TXNS };
    let job = match lookup {
        Ok(job) => job,
        Err((idx, status)) => return TxnBundle::empty(selector, idx, status),
    };
    let txns = &job.template.txns;
    let ids = if all { Some((0..txns.len()).collect()) } else { requested_ids(plain, txns.len()) };
    match ids {
        Some(ids) => TxnBundle {
            selector,
            job_index: job.datum_slot,
            status: Status::Ok,
            txns: ids.iter().map(|&i| txns[i].raw.clone()).collect(),
        },
        None => TxnBundle::empty(selector, job.datum_slot, Status::BadRequest),
    }
}

fn requested_ids(plain: &[u8], txn_count: usize) -> Option<Vec<usize>> {
    let mut c = ratum::cursor::Cursor::new(plain.get(validation::REQUEST_HEADER_LEN..)?);
    let count = usize::from(c.u16("index count").ok()?);
    if count == 0 || count > txn_count {
        return None;
    }
    let ids: Vec<usize> = c
        .take(count * size_of::<u16>(), "indexes")
        .ok()?
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| usize::from(u16::from_le_bytes(*b)))
        .collect();
    ids.iter().all(|&i| i < txn_count).then_some(ids)
}
