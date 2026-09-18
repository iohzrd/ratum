//! A block a miner found: assembled from its job and header, submitted to the node twice and to
//! every extra node, saved where configured, and checked against the best chain two minutes later.

use crate::gateway::Gateway;
use crate::job::{CoinbaseKind, Job};
use log::{debug, error, info, warn};
use ratum::rpc;
use std::sync::Arc;
use std::time::Duration;

const CONFIRM_AFTER: Duration = Duration::from_secs(2 * ratum::SECS_PER_MINUTE);

pub fn found_block(
    gateway: &Arc<Gateway>,
    job: &Job,
    kind: CoinbaseKind,
    target_byte: u8,
    header: &[u8; ratum::header::HEADER_V2_SIZE],
    hash_hex: &str,
) {
    let Some(block) = assemble(job, kind, target_byte, header) else {
        error!("could not assemble the block for {hash_hex}");
        return;
    };
    debug!("Block Payload: {}", hex::encode(&block));
    let block = Arc::new(block);
    spawn_redundant(gateway, Arc::clone(&block), hash_hex);
    let dir = &gateway.config.mining.save_submitblocks_dir;
    if !dir.is_empty() {
        save_to_dir(dir, hash_hex, &block);
    }
    if submit_to(&gateway.node, "upstream node", &block, hash_hex) {
        gateway.template_waker.raise_for(hash_hex);
        spawn_confirmation(gateway.node.clone(), hash_hex);
    }
}

fn spawn_confirmation(node: rpc::Client, hash_hex: &str) {
    let hash_hex = hash_hex.to_string();
    ratum::thread::spawn_or_warn("block-confirm", move || {
        std::thread::sleep(CONFIRM_AFTER);
        let secs = CONFIRM_AFTER.as_secs();
        match node.block_confirmations(&hash_hex) {
            Ok(Some(confirmations)) if rpc::on_best_chain(confirmations) => {
                info!(
                    "Block {hash_hex} is on the best chain {secs}s later ({confirmations} confirmations)"
                )
            }
            Ok(Some(_)) => error!(
                "Block {hash_hex} is NOT on the best chain {secs}s after the node accepted it: another block won the height and this one pays nothing"
            ),
            Ok(None) => warn!(
                "the node stores no block under {hash_hex} {secs}s after accepting it; it cannot be checked against the best chain"
            ),
            Err(e) => warn!("could not check block {hash_hex} against the best chain: {e}"),
        }
    });
}

fn assemble(
    job: &Job,
    kind: CoinbaseKind,
    target_byte: u8,
    header: &[u8; ratum::header::HEADER_V2_SIZE],
) -> Option<Vec<u8>> {
    let coinbase = job.full_coinbase(kind, target_byte)?;
    let others: Vec<Vec<u8>> = match kind {
        CoinbaseKind::SubsidyOnly => Vec::new(),
        CoinbaseKind::Pooled => job.template.txns.iter().map(|t| t.raw.clone()).collect(),
    };
    Some(ratum::bitcoin::serialize_block(header, &coinbase, &others))
}

fn submit_to(node: &rpc::Client, what: &str, block: &[u8], hash_hex: &str) -> bool {
    let accepted = match node.submit_block(block) {
        Ok(None) => {
            info!("Block {hash_hex} submitted to {what} successfully!");
            true
        }
        Ok(Some(reason)) if reason == "duplicate" => {
            info!("Block {hash_hex} already known to {what}");
            true
        }
        Ok(Some(reason)) => {
            warn!("{what} rejected our block! ({reason})");
            false
        }
        Err(e) => {
            warn!("could not submit block {hash_hex} to {what}: {e}");
            false
        }
    };
    match node.call("preciousblock", serde_json::json!([hash_hex])) {
        Ok(_) => debug!("preciousblock {hash_hex} sent to {what}"),
        Err(e) => debug!("preciousblock to {what} failed: {e}"),
    }
    accepted
}

fn spawn_redundant(gateway: &Arc<Gateway>, block: Arc<Vec<u8>>, hash_hex: &str) {
    let (gateway, hash_hex) = (Arc::clone(gateway), hash_hex.to_string());
    ratum::thread::spawn_or_warn("submitblock", move || {
        if submit_to(&gateway.node, "upstream node (redundant)", &block, &hash_hex) {
            gateway.template_waker.raise_for(&hash_hex);
        }
        for (i, extra) in gateway.extra_nodes.iter().enumerate() {
            submit_to(extra, &format!("extra node {i}"), &block, &hash_hex);
        }
    });
}

fn save_to_dir(dir: &str, hash_hex: &str, block: &[u8]) {
    let path = format!("{dir}/datum_submitblock_{hash_hex}.json");
    let body = serde_json::json!({
        "jsonrpc": "1.0", "id": hash_hex, "method": "submitblock", "params": [hex::encode(block)]
    });
    if let Err(e) = std::fs::write(&path, body.to_string()) {
        warn!("could not save the block submission to {path}: {e}");
    }
}
