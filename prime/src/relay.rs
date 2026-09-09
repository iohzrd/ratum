use log::{debug, error, info, warn};
use ratum::rpc;
use ratum_prime::verify::AcceptedShare;
use std::net::SocketAddr;
use std::time::Duration;

const SUBMIT_ATTEMPTS: usize = 3;
const SUBMIT_RETRY_DELAY: Duration = Duration::from_millis(500);

pub(crate) fn submit_or_request_txns(
    peer: SocketAddr,
    node: &rpc::Client,
    a: &AcceptedShare,
    subsidy_only: bool,
) -> bool {
    let template_txns = a.work.txn_count;
    if !subsidy_only && template_txns != 0 {
        info!("[{peer}]      block has {template_txns} more transactions; requesting them");
        return true;
    }
    send(peer, node, &ratum::bitcoin::serialize_block(&a.work.header, &a.work.coinbase_tx, &[]));
    false
}

pub(crate) fn submit_with_txns(
    peer: SocketAddr,
    node: &rpc::Client,
    job_index: u8,
    a: &AcceptedShare,
    txns: &[Vec<u8>],
) {
    if let Err(why) = block_matches_header(a, txns) {
        error!("[{peer}]      not relaying job {job_index}: {why}");
        return;
    }
    send(peer, node, &ratum::bitcoin::serialize_block(&a.work.header, &a.work.coinbase_tx, txns));
}

fn block_matches_header(a: &AcceptedShare, txns: &[Vec<u8>]) -> Result<(), String> {
    let committed = ratum::header::HeaderV2::deserialize(&a.work.header)
        .ok_or_else(|| "the header does not deserialize".to_string())?
        .merkle_root;

    let mut ids = Vec::with_capacity(txns.len() + 1);
    ids.push(ratum::bitcoin::sha256d(&a.work.coinbase_tx));
    for (i, raw) in txns.iter().enumerate() {
        match ratum::bitcoin::txid(raw) {
            Ok(id) => ids.push(id),
            Err(e) => return Err(format!("transaction {i} does not decode: {e}")),
        }
    }
    let count = ids.len();
    let (built, mutated) = ratum::bitcoin::merkle_root_of(&ids).ok_or("no transactions")?;
    if mutated {
        return Err(format!(
            "{count} transactions form a mutated merkle tree (duplicate hashes); \
             the node would reject the block"
        ));
    }
    if built != committed {
        return Err(format!(
            "{count} transactions have merkle root {}, but the header commits to {}",
            ratum::header::u256_to_display_hex(&built),
            ratum::header::u256_to_display_hex(&committed)
        ));
    }
    Ok(())
}

fn send(peer: SocketAddr, node: &rpc::Client, block: &[u8]) {
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
