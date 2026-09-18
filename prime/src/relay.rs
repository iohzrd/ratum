//! Submitting a verified block to the node, after checking that the transactions the gateway sent
//! form the merkle root its header commits to.

use crate::verify::RebuiltShare;
use log::{debug, error, info, warn};
use ratum::rpc;
use std::net::SocketAddr;
use std::time::Duration;

const SUBMIT_ATTEMPTS: usize = 3;
const SUBMIT_RETRY_DELAY: Duration = Duration::from_millis(500);

/// Submits the block of `rebuilt` with the job's other transactions `txns`, once they form
/// the merkle root its header commits to.
pub fn submit(
    peer: SocketAddr,
    node: &rpc::Client,
    job_index: u8,
    rebuilt: &RebuiltShare,
    txns: &[Vec<u8>],
) {
    if let Err(why) = block_matches_header(rebuilt, txns) {
        error!("[{peer}]      not relaying job {job_index}: {why}");
        return;
    }
    submit_with_retries(
        peer,
        node,
        &ratum::bitcoin::serialize_block(&rebuilt.header, &rebuilt.coinbase_tx, txns),
    );
}

fn block_matches_header(rebuilt: &RebuiltShare, txns: &[Vec<u8>]) -> Result<(), String> {
    let committed = ratum::header::BlockHeaderV2::deserialize(&rebuilt.header)
        .ok_or_else(|| "the header does not deserialize".to_string())?
        .merkle_root;

    let mut ids = Vec::with_capacity(txns.len() + 1);
    ids.push(ratum::bitcoin::sha256d(&rebuilt.coinbase_tx));
    for (i, raw) in txns.iter().enumerate() {
        match ratum::bitcoin::transaction::txid(raw) {
            Ok(id) => ids.push(id),
            Err(e) => return Err(format!("transaction {i} does not decode: {e}")),
        }
    }
    let count = ids.len();
    let tree = ratum::bitcoin::merkle_tree_root(&ids).ok_or("no transactions")?;
    if tree.mutated {
        return Err(format!(
            "{count} transactions form a mutated merkle tree (duplicate hashes); \
             the node would reject the block"
        ));
    }
    if tree.root != committed {
        return Err(format!(
            "{count} transactions have merkle root {}, but the header commits to {}",
            ratum::bitcoin::hash_to_display_hex(&tree.root),
            ratum::bitcoin::hash_to_display_hex(&committed)
        ));
    }
    Ok(())
}

fn submit_with_retries(peer: SocketAddr, node: &rpc::Client, block: &[u8]) {
    debug!("[{peer}]      block ({} bytes): {}", block.len(), hex::encode(block));
    for attempt in 1..=SUBMIT_ATTEMPTS {
        match node.submit_block(block) {
            Ok(None) => {
                info!("[{peer}]      submitted: node accepted the block");
                return;
            }
            Ok(Some(reason)) => {
                warn!("[{peer}]      submitted: node rejected the block ({reason:?})");
                return;
            }
            Err(e) if e.is_unauthorized() => {
                error!(
                    "[{peer}]      could not relay: the node refused the pool's RPC credential \
                     ({e}); if the node has restarted, its cookie has changed"
                );
                break;
            }
            Err(e) => {
                warn!("[{peer}]      could not relay (attempt {attempt}/{SUBMIT_ATTEMPTS}): {e}");
                if attempt < SUBMIT_ATTEMPTS {
                    std::thread::sleep(SUBMIT_RETRY_DELAY);
                }
            }
        }
    }
    error!(
        "[{peer}]      stopped relaying the block after {SUBMIT_ATTEMPTS} attempts; resubmit with \
         submitblock: {}",
        hex::encode(block)
    );
}
