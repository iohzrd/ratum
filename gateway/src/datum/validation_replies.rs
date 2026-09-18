//! Answering the pool's job validation requests (0x50) from the template a job was built on: its
//! short transaction list, transactions by index, all of them, or the parent block read from the
//! node.

use crate::gateway::Gateway;
use crate::job::Job;
use log::{info, warn};
use ratum::bitcoin::hash_to_display_hex;
use ratum::datum::keys::KeyPairs;
use ratum::datum::messages::validation::{
    self, ParentFetchReply, ParentFetchStatus, ShortTxnList, TxnList, TxnListStatus,
};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SlotLookupFailure {
    job_index: u8,
    status: TxnListStatus,
}

fn job_slot(gateway: &Gateway, index: u8) -> Result<Arc<Job>, SlotLookupFailure> {
    if usize::from(index) >= gateway.config.datum.protocol_job_slots {
        return Err(SlotLookupFailure {
            job_index: validation::JOB_INDEX_INVALID,
            status: TxnListStatus::BadJobIndex,
        });
    }
    gateway
        .jobs
        .at(index)
        .ok_or(SlotLookupFailure { job_index: index, status: TxnListStatus::JobEmpty })
}

pub(super) fn response_to(
    gateway: &Gateway,
    pool_sign_pk: &[u8; 32],
    identity: &KeyPairs,
    plain: &[u8],
) -> Option<Vec<u8>> {
    let sub = *plain.get(validation::SELECTOR_AT)?;
    let job_index = plain.get(validation::JOB_INDEX_AT).copied();
    let lookup = job_index
        .ok_or(SlotLookupFailure {
            job_index: validation::JOB_INDEX_INVALID,
            status: TxnListStatus::BadRequest,
        })
        .and_then(|i| job_slot(gateway, i));
    let response = match sub {
        validation::request::SHORT_TXN_LIST => {
            info!("pool requested the short transaction list of job {job_index:?}");
            match lookup {
                Ok(job) => short_txn_list(pool_sign_pk, identity, &job),
                Err(failure) => ShortTxnList::empty(failure.job_index, failure.status),
            }
            .encode()
        }
        validation::request::TXNS | validation::request::BLOCK_TXNS => {
            let all = sub == validation::request::BLOCK_TXNS;
            let list = txn_list(lookup, plain, all);
            info!(
                "pool requested {} of job {job_index:?}: sending {}",
                if all { "the block transactions" } else { "transactions" },
                list.txns.len()
            );
            list.encode()
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
                    fetch_parent(&gateway.node, &hash_to_display_hex(&job.template.prev_hash))
                }
                _ => (ParentFetchStatus::JobMismatch, Vec::new()),
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

fn fetch_parent(node: &ratum::rpc::Client, hash_hex: &str) -> (ParentFetchStatus, Vec<u8>) {
    match node.call("getblock", serde_json::json!([hash_hex, 0])) {
        Ok(serde_json::Value::String(hex)) => match hex::decode(&hex) {
            Ok(block)
                if !block.is_empty() && block.len() <= validation::MAX_PARENT_FETCH_BLOCK_LEN =>
            {
                (ParentFetchStatus::Success, block)
            }
            _ => (ParentFetchStatus::RpcFailed, Vec::new()),
        },
        Ok(_) => (ParentFetchStatus::RpcFailed, Vec::new()),
        Err(e) => {
            warn!("getblock for the parent fetch failed: {e}");
            (ParentFetchStatus::Unavailable, Vec::new())
        }
    }
}

fn short_txn_list(pool_sign_pk: &[u8; 32], identity: &KeyPairs, job: &Job) -> ShortTxnList {
    let hashes = job.template.witness_hashes();
    if hashes.len() > validation::MAX_SHORT_LIST_TXNS as usize {
        return ShortTxnList::empty(job.slot, TxnListStatus::TooManyTxns);
    }
    let key = validation::short_id_key(&identity.sign_pk, pool_sign_pk);
    ShortTxnList {
        job_index: job.slot,
        status: TxnListStatus::Ok,
        short_ids: hashes.iter().map(|h| validation::short_id(h, &key)).collect(),
        crosscheck: if hashes.is_empty() { None } else { Some(validation::crosscheck(&hashes)) },
    }
}

fn txn_list(lookup: Result<Arc<Job>, SlotLookupFailure>, plain: &[u8], all: bool) -> TxnList {
    let selector = if all { validation::response::BLOCK_TXNS } else { validation::response::TXNS };
    let job = match lookup {
        Ok(job) => job,
        Err(failure) => return TxnList::empty(selector, failure.job_index, failure.status),
    };
    let txns = &job.template.txns;
    let ids = if all { Some((0..txns.len()).collect()) } else { requested_ids(plain, txns.len()) };
    match ids {
        Some(ids) => TxnList {
            selector,
            job_index: job.slot,
            status: TxnListStatus::Ok,
            txns: ids.iter().map(|&i| txns[i].raw.clone()).collect(),
        },
        None => TxnList::empty(selector, job.slot, TxnListStatus::BadRequest),
    }
}

fn requested_ids(plain: &[u8], txn_count: usize) -> Option<Vec<usize>> {
    let mut c = ratum::reader::ByteReader::new(plain.get(validation::REQUEST_HEADER_LEN..)?);
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
