//! Block assembly and `submitblock`: to the local node, then to any extra node configured,
//! with `preciousblock` after each.

use crate::job::{COINBASE_SUBSIDY_ONLY, Job};
use log::{debug, info, warn};
use ratum::rpc;

/// The serialized block a share names: the header, the transaction count, the coinbase
/// (without witness; the node adds the witness nonce in `submitblock`), then the template's
/// transactions unless the work was subsidy-only.
pub fn assemble(job: &Job, coinbase_id: u8, pot: u8, header: &[u8; 164]) -> Option<Vec<u8>> {
    let coinbase = job.full_coinbase(coinbase_id, pot)?;
    let empty = coinbase_id == COINBASE_SUBSIDY_ONLY;
    let others: Vec<Vec<u8>> =
        if empty { Vec::new() } else { job.template.txns.iter().map(|t| t.raw.clone()).collect() };
    Some(ratum::bitcoin::serialize_block(header, &coinbase, &others))
}

/// Submit to one node; `true` when the node accepted it.
pub fn submit_to(node: &rpc::Client, what: &str, block: &[u8], hash_hex: &str) -> bool {
    let accepted = match node.submit_block(block) {
        Ok(None) => {
            info!("Block {hash_hex} submitted to {what} successfully!");
            true
        }
        // "duplicate" is the node's response to the second of two submissions of one block
        // (the C gateway's submitblock thread and its inline call overlap the same way).
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

/// The C gateway's submitblock thread: submit to the node again on its own connection, then
/// to every extra node, without holding up the stratum thread that found the block. The
/// template thread is notified when the node accepts it.
pub fn submit_redundant(
    node: rpc::Client,
    extras: Vec<rpc::Client>,
    block: std::sync::Arc<Vec<u8>>,
    hash_hex: String,
    notify: std::sync::Arc<crate::template::Notify>,
) {
    let spawned = std::thread::Builder::new().name("submitblock".into()).spawn(move || {
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

/// A client for an extra submission URL: `http://host[:port]` or `https://host[:port]`,
/// optionally with `user:pass@` before the host, the forms the C gateway hands to curl.
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
    // Without a port, the scheme's, as curl applies for the C gateway.
    let (authority, path) = host.split_once('/').map_or((host, ""), |(a, p)| (a, p));
    if authority.is_empty() {
        return None;
    }
    let has_port = authority.rsplit_once(']').map_or(authority, |(_, after)| after).contains(':');
    let port = if has_port {
        String::new()
    } else if scheme == "https" {
        ":443".to_string()
    } else {
        ":80".to_string()
    };
    let slash = if path.is_empty() && !host.contains('/') { "" } else { "/" };
    rpc::Client::new(&format!("{scheme}://{authority}{port}{slash}{path}"), user, pass).ok()
}

pub fn save_to_dir(dir: &str, hash_hex: &str, block: &[u8]) {
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
