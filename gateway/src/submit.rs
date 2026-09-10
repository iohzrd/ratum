use crate::job::{COINBASE_SUBSIDY_ONLY, Job};
use crate::stratum::Server;
use log::{debug, error, info, warn};
use ratum::rpc;
use std::sync::Arc;

pub fn found_block(
    server: &Server,
    job: &Job,
    coinbase_id: u8,
    pot: u8,
    header: &[u8; ratum::header::HEADER_V2_SIZE],
    hash_hex: &str,
) {
    let Some(block) = assemble(job, coinbase_id, pot, header) else {
        error!("could not assemble the block for {hash_hex}");
        return;
    };
    debug!("Block Payload: {}", hex::encode(&block));
    let block = Arc::new(block);
    spawn_redundant(server, Arc::clone(&block), hash_hex);
    let dir = &server.config.mining.save_submitblocks_dir;
    if !dir.is_empty() {
        save_to_dir(dir, hash_hex, &block);
    }
    if submit_to(&server.node, "upstream node", &block, hash_hex) {
        server.notify.raise_for(hash_hex);
    }
}

fn assemble(
    job: &Job,
    coinbase_id: u8,
    pot: u8,
    header: &[u8; ratum::header::HEADER_V2_SIZE],
) -> Option<Vec<u8>> {
    let coinbase = job.full_coinbase(coinbase_id, pot)?;
    let empty = coinbase_id == COINBASE_SUBSIDY_ONLY;
    let others: Vec<Vec<u8>> =
        if empty { Vec::new() } else { job.template.txns.iter().map(|t| t.raw.clone()).collect() };
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

fn spawn_redundant(server: &Server, block: Arc<Vec<u8>>, hash_hex: &str) {
    let (node, extras) = (server.node.clone(), server.extra_nodes.clone());
    let (notify, hash_hex) = (Arc::clone(&server.notify), hash_hex.to_string());
    let spawned = ratum::thread::try_spawn("submitblock", move || {
        if submit_to(&node, "upstream node (redundant)", &block, &hash_hex) {
            notify.raise_for(&hash_hex);
        }
        for (i, extra) in extras.iter().enumerate() {
            submit_to(extra, &format!("extra node {i}"), &block, &hash_hex);
        }
    });
    if let Err(e) = spawned {
        warn!("could not start the redundant submitblock thread: {e}");
    }
}

pub fn extra_client(url: &str) -> Option<rpc::Client> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let (user, pass, host) = match rest.rsplit_once('@') {
        Some((creds, host)) => {
            let (user, pass) = creds.split_once(':').unwrap_or((creds, ""));
            (user, pass, host)
        }
        None => ("", "", rest),
    };
    let (authority, path) = match host.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (host, String::new()),
    };
    if authority.is_empty() {
        return None;
    }
    let has_port = authority.rsplit_once(']').map_or(authority, |(_, after)| after).contains(':');
    let port = match (has_port, scheme) {
        (true, _) => String::new(),
        (false, "https") => format!(":{HTTPS_PORT}"),
        (false, _) => format!(":{HTTP_PORT}"),
    };
    rpc::Client::new(&format!("{scheme}://{authority}{port}{path}"), user, pass).ok()
}

const HTTP_PORT: u16 = 80;
const HTTPS_PORT: u16 = 443;

fn save_to_dir(dir: &str, hash_hex: &str, block: &[u8]) {
    let path = format!("{dir}/datum_submitblock_{hash_hex}.json");
    let body = serde_json::json!({
        "jsonrpc": "1.0", "id": hash_hex, "method": "submitblock", "params": [hex::encode(block)]
    });
    if let Err(e) = std::fs::write(&path, body.to_string()) {
        warn!("could not save the block submission to {path}: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::extra_client;

    #[test]
    fn extra_urls_take_both_schemes_and_optional_credentials() {
        assert!(extra_client("http://u:p@127.0.0.1:8332").is_some());
        assert!(extra_client("https://u:p@node.example:8332").is_some());
        assert!(extra_client("http://127.0.0.1:8332").is_some());
        assert!(extra_client("ftp://127.0.0.1:8332").is_none());
        assert!(extra_client("127.0.0.1:8332").is_none());
        assert!(extra_client("http://nohost").is_some(), "the scheme's port applies");
        assert!(extra_client("http://").is_none());
    }
}
