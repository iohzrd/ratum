//! Submitting a verified block to the node, after checking that the transactions the gateway sent
//! form the merkle root its header commits to, and asking the node whether a job's block is valid
//! before any share on the job is credited.

use crate::verify::RebuiltShare;
use log::{debug, error, info, warn};
use ratum::bitcoin::transaction::parse_coinbase;
use ratum::rpc;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

const SUBMIT_ATTEMPTS: usize = 3;
const SUBMIT_RETRY_DELAY: Duration = Duration::from_millis(500);
const PROPOSAL_ATTEMPTS: usize = 2;

/// The start of a segwit coinbase's witness commitment output script (BIP 141): OP_RETURN,
/// a 36-byte push, and the commitment header.
const WITNESS_COMMITMENT_PREFIX: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
const SEGWIT_MARKER_AND_FLAG: [u8; 2] = [0x00, 0x01];
/// The coinbase input's witness: one stack item, the 32-byte witness reserved value of zeros.
const WITNESS_RESERVED_VALUE_STACK: [u8; 34] = {
    let mut stack = [0u8; 34];
    stack[0] = 1;
    stack[1] = 32;
    stack
};
const TX_VERSION_LEN: usize = 4;
const TX_LOCK_TIME_LEN: usize = 4;

/// What the node did with a block the pool submitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Relayed {
    /// `submitblock` answered null: the node accepted the block.
    Accepted,
    /// The node refused the block, or the pool did not submit it because its transactions do
    /// not form the header's merkle root.
    Rejected(String),
    /// No answer from the node after every attempt: whether it holds the block is unknown.
    Unknown,
}

/// Submits the block of `rebuilt` with the job's other transactions `txns`, once they form
/// the merkle root its header commits to.
pub fn submit(
    peer: SocketAddr,
    node: &rpc::Client,
    job_index: u8,
    rebuilt: &RebuiltShare,
    txns: &[Arc<[u8]>],
) -> Relayed {
    if let Err(why) = block_matches_header(rebuilt, txns) {
        error!("[{peer}]      not relaying job {job_index}: {why}");
        return Relayed::Rejected(why);
    }
    submit_with_retries(
        peer,
        node,
        &ratum::bitcoin::serialize_block(&rebuilt.header, &rebuilt.coinbase_tx, txns),
    )
}

/// The node's verdict on the block of `rebuilt` with `txns`, proof of work aside: none when it
/// is valid, otherwise the node's reason. The coinbase carries the witness reserved value when
/// it commits to witnesses, as `submitblock` adds it and a proposal is checked without it.
pub fn propose(
    node: &rpc::Client,
    rebuilt: &RebuiltShare,
    txns: &[Arc<[u8]>],
) -> Result<Option<String>, rpc::Error> {
    let coinbase = with_witness_reserved_value(&rebuilt.coinbase_tx);
    let block = ratum::bitcoin::serialize_block(&rebuilt.header, &coinbase, txns);
    let mut attempt = 1;
    loop {
        match node.propose_block(&block) {
            Err(e) if attempt < PROPOSAL_ATTEMPTS && !e.is_unauthorized() => {
                debug!("block proposal failed (attempt {attempt}/{PROPOSAL_ATTEMPTS}): {e}");
                attempt += 1;
            }
            result => return result,
        }
    }
}

/// `coinbase` with a witness carrying the 32-byte witness reserved value when one of its
/// outputs is a witness commitment; unchanged otherwise, and when it does not parse or
/// already carries a witness.
fn with_witness_reserved_value(coinbase: &[u8]) -> Vec<u8> {
    let commits = parse_coinbase(coinbase).is_ok_and(|tx| {
        !tx.has_witness
            && tx
                .outputs
                .iter()
                .any(|out| out.script_pubkey.starts_with(&WITNESS_COMMITMENT_PREFIX))
    });
    if !commits || coinbase.len() < TX_VERSION_LEN + TX_LOCK_TIME_LEN {
        return coinbase.to_vec();
    }
    let lock_time_at = coinbase.len() - TX_LOCK_TIME_LEN;
    let mut out = Vec::with_capacity(
        coinbase.len() + SEGWIT_MARKER_AND_FLAG.len() + WITNESS_RESERVED_VALUE_STACK.len(),
    );
    out.extend_from_slice(&coinbase[..TX_VERSION_LEN]);
    out.extend_from_slice(&SEGWIT_MARKER_AND_FLAG);
    out.extend_from_slice(&coinbase[TX_VERSION_LEN..lock_time_at]);
    out.extend_from_slice(&WITNESS_RESERVED_VALUE_STACK);
    out.extend_from_slice(&coinbase[lock_time_at..]);
    out
}

/// Checks that `txns` are the job's transactions: their count and their merkle branch on the
/// coinbase's side of the tree are the ones the job section carries.
pub fn txns_match_job(
    txns: &[Arc<[u8]>],
    txn_count: u32,
    merkle_branches: &[[u8; 32]],
) -> Result<(), String> {
    if txns.len() != txn_count as usize {
        return Err(format!("{} transactions for a job of {txn_count}", txns.len()));
    }
    let mut ids = Vec::with_capacity(txns.len());
    for (i, raw) in txns.iter().enumerate() {
        match ratum::bitcoin::transaction::txid(raw) {
            Ok(id) => ids.push(id),
            Err(e) => return Err(format!("transaction {i} does not decode: {e}")),
        }
    }
    if ratum::bitcoin::merkle_branches(&ids) != merkle_branches {
        return Err("the transactions do not form the job's merkle branches".to_string());
    }
    Ok(())
}

fn block_matches_header(rebuilt: &RebuiltShare, txns: &[Arc<[u8]>]) -> Result<(), String> {
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

fn submit_with_retries(peer: SocketAddr, node: &rpc::Client, block: &[u8]) -> Relayed {
    debug!("[{peer}]      block ({} bytes): {}", block.len(), hex::encode(block));
    for attempt in 1..=SUBMIT_ATTEMPTS {
        match node.submit_block(block) {
            Ok(None) => {
                info!("[{peer}]      submitted: node accepted the block");
                return Relayed::Accepted;
            }
            Ok(Some(reason)) => {
                warn!("[{peer}]      submitted: node rejected the block ({reason:?})");
                return Relayed::Rejected(reason);
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
    Relayed::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratum::bitcoin::transaction::TxOut;

    fn coinbase_paying(outputs: &[TxOut]) -> Vec<u8> {
        let mut tx = vec![0x01, 0, 0, 0, 0x01];
        tx.extend_from_slice(&[0u8; 32]);
        tx.extend_from_slice(&[0xff; 4]);
        tx.extend_from_slice(&[0x04, 0x03, 0x01, 0x02, 0x03]);
        tx.extend_from_slice(&[0xff; 4]);
        tx.push(outputs.len() as u8);
        for out in outputs {
            tx.extend_from_slice(&out.value.to_le_bytes());
            tx.push(out.script_pubkey.len() as u8);
            tx.extend_from_slice(&out.script_pubkey);
        }
        tx.extend_from_slice(&[0u8; 4]);
        tx
    }

    #[test]
    fn a_coinbase_committing_to_witnesses_gets_the_reserved_value() {
        let mut commitment = WITNESS_COMMITMENT_PREFIX.to_vec();
        commitment.extend_from_slice(&[0x77; 32]);
        let plain = coinbase_paying(&[TxOut { value: 5, script_pubkey: vec![0x51] }]);
        assert_eq!(with_witness_reserved_value(&plain), plain, "no commitment, no witness");

        let committing = coinbase_paying(&[
            TxOut { value: 5, script_pubkey: vec![0x51] },
            TxOut { value: 0, script_pubkey: commitment },
        ]);
        let with_witness = with_witness_reserved_value(&committing);
        let parsed = parse_coinbase(&with_witness).expect("a segwit coinbase");
        assert!(parsed.has_witness);
        assert_eq!(parsed.outputs, parse_coinbase(&committing).unwrap().outputs);
        assert_eq!(
            ratum::bitcoin::transaction::txid(&with_witness).unwrap(),
            ratum::bitcoin::sha256d(&committing),
            "the witness does not change the txid the merkle root commits to"
        );
        assert_eq!(with_witness_reserved_value(&with_witness), with_witness, "added once");
    }

    #[test]
    fn transactions_match_a_job_by_count_and_merkle_branches() {
        let txns: Vec<Arc<[u8]>> = (1u8..=3)
            .map(|n| {
                Arc::from(coinbase_paying(&[TxOut { value: n.into(), script_pubkey: vec![n] }]))
            })
            .collect();
        let ids: Vec<[u8; 32]> =
            txns.iter().map(|t| ratum::bitcoin::transaction::txid(t).unwrap()).collect();
        let branches = ratum::bitcoin::merkle_branches(&ids);
        assert!(txns_match_job(&txns, 3, &branches).is_ok());
        assert!(txns_match_job(&txns, 4, &branches).is_err(), "the count differs");
        assert!(txns_match_job(&txns[..2], 2, &branches).is_err(), "the branches differ");
        let mut reordered = txns.clone();
        reordered.swap(0, 1);
        assert!(txns_match_job(&reordered, 3, &branches).is_err(), "the order is committed to");
    }
}
