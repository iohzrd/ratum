//! The block template: `getblocktemplate` and its checks, and the thread that polls the
//! node, reacts to block notifications, and passes each template to the job builder.

use crate::config::Config;
use log::{debug, error, info, warn};
use ratum::rpc;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

pub const MAX_TXNS: usize = 16383;

#[derive(Clone, Debug)]
pub struct Txn {
    pub raw: Vec<u8>,
    /// The txid in internal byte order.
    pub txid: [u8; 32],
    /// The witness hash in internal byte order.
    pub hash: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct Template {
    pub height: u32,
    pub coinbase_value: u64,
    pub txn_total_fee: u64,
    pub mintime: u64,
    pub curtime: u64,
    pub sizelimit: u64,
    pub weightlimit: u64,
    pub sigoplimit: u64,
    pub version: u32,
    /// The `bits` string as the node sent it.
    pub bits: String,
    pub nbits: u32,
    /// `nbits` little-endian, the bytes the job section carries.
    pub nbits_bytes: [u8; 4],
    pub prev_hash_hex: String,
    /// The previous block hash in internal byte order.
    pub prev_hash: [u8; 32],
    pub target_hex: String,
    pub witness_commitment: Vec<u8>,
    pub reduced_data: bool,
    pub txns: Vec<Txn>,
    pub txn_total_weight: u32,
    pub txn_total_size: u32,
    pub txn_total_sigops: u32,
}

impl Template {
    pub fn txn_hashes(&self) -> Vec<[u8; 32]> {
        self.txns.iter().map(|t| t.hash).collect()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    #[error("Missing data from GBT JSON ({0})")]
    Missing(&'static str),
    #[error("{0}")]
    Refused(String),
    #[error("DATUM Gateway does not support blocks with more than {MAX_TXNS} transactions")]
    TooManyTxns,
}

fn u64_field(v: &serde_json::Value, key: &'static str) -> Result<u64, TemplateError> {
    match v[key].as_u64() {
        Some(n) if n != 0 => Ok(n),
        _ => Err(TemplateError::Missing(key)),
    }
}

fn str_field<'a>(
    v: &'a serde_json::Value,
    key: &'static str,
    len: std::ops::RangeInclusive<usize>,
) -> Result<&'a str, TemplateError> {
    match v[key].as_str() {
        Some(s) if len.contains(&s.len()) => Ok(s),
        _ => Err(TemplateError::Missing(key)),
    }
}

fn rule_present(v: &serde_json::Value, rule: &str) -> bool {
    v["rules"].as_array().is_some_and(|a| a.iter().any(|r| r.as_str() == Some(rule)))
}

/// What the parser reports once per height so a repeated template does not repeat a message.
#[derive(Default)]
pub struct Announced {
    activation: Option<u32>,
    rules: Option<u32>,
    payout: Option<u32>,
}

/// Parse a `getblocktemplate` result, with the C gateway's checks (`datum_gbt_parser`).
/// `payout_script` is the pool payout script the `reduced_data` check sizes.
pub fn parse(
    v: &serde_json::Value,
    config: &Config,
    payout_script: &[u8],
    announced: &mut Announced,
) -> Result<Template, TemplateError> {
    let height = u64_field(v, "height")? as u32;
    let activation = config.mining.blake2b_activation_height;

    // The headline the node will enforce at the activation block, from coinbaseaux.
    match v["coinbaseaux"]["blake2b_headline"].as_str() {
        None => {
            if height == activation {
                return Err(TemplateError::Refused(format!(
                    "Node published no BLAKE2b headline for block {height}, which mining.blake2b_activation_height names as the activation height. Either the node is not the BLAKE2b build or the configured height is wrong. Serving no work for this block."
                )));
            }
        }
        Some(hex_headline) => {
            if height != activation {
                return Err(TemplateError::Refused(format!(
                    "Node template: block {height} activates BLAKE2b, but mining.blake2b_activation_height is {activation}. Serving no work for this block."
                )));
            }
            let bytes = hex::decode(hex_headline).map_err(|_| {
                TemplateError::Refused("Node published a BLAKE2b headline that is not hex".into())
            })?;
            if bytes.len() >= 128 {
                return Err(TemplateError::Refused(
                    "Node published a BLAKE2b headline over 127 bytes".into(),
                ));
            }
            if bytes != config.mining.blake2b_headline.as_bytes() {
                return Err(TemplateError::Refused(format!(
                    "BLAKE2b headline mismatch at the activation block: the node will enforce {:?}, mining.blake2b_headline is {:?}. Serving no work for this block.",
                    String::from_utf8_lossy(&bytes),
                    config.mining.blake2b_headline
                )));
            }
            if announced.activation != Some(height) {
                announced.activation = Some(height);
                info!(
                    "Block {height} activates BLAKE2b, and the configured headline is the one the node will enforce."
                );
            }
        }
    }

    let expected = height >= activation;
    let node_v2 = rule_present(v, "!blake2b");
    if expected != node_v2 {
        if announced.rules != Some(height) {
            announced.rules = Some(height);
            if node_v2 {
                error!(
                    "Node requires the BLAKE2b (version 2) header for block {height}, but mining.blake2b_activation_height is {activation}, below which this Gateway serves no work. The configured height is too high."
                );
            } else {
                error!(
                    "Node does not list the !blake2b rule for block {height}, but mining.blake2b_activation_height is {activation}, so this Gateway would build a version 2 header that the node rejects as bad-version-sha256d. The configured height is too low."
                );
            }
        }
        return Err(TemplateError::Refused(format!("BLAKE2b rule mismatch at block {height}")));
    }

    let reduced_data = rule_present(v, "reduced_data");
    if reduced_data && !ratum::bitcoin::output_script_size_is_valid(payout_script) {
        if announced.payout != Some(height) {
            announced.payout = Some(height);
            error!(
                "Pool payout output script is {} bytes, but the node enforces the reduced_data rule for block {height}, which limits a non-OP_RETURN coinbase output script to 34 bytes. Serving no work for this block.",
                payout_script.len()
            );
        }
        return Err(TemplateError::Refused("payout script over the reduced_data limit".into()));
    }

    let coinbase_value = u64_field(v, "coinbasevalue")?;
    let mintime = u64_field(v, "mintime")?;
    let sigoplimit = u64_field(v, "sigoplimit")?;
    let curtime = u64_field(v, "curtime")?;
    let sizelimit = u64_field(v, "sizelimit")?;
    let weightlimit = u64_field(v, "weightlimit")?;
    let version = u64_field(v, "version")? as u32;
    let bits = str_field(v, "bits", 8..=8)?.to_string();
    let prev_hash_hex = str_field(v, "previousblockhash", 64..=64)?.to_string();
    let target_hex = str_field(v, "target", 64..=64)?.to_string();
    let wc_hex = str_field(v, "default_witness_commitment", 38..=95)?;
    let witness_commitment =
        hex::decode(wc_hex).map_err(|_| TemplateError::Missing("default_witness_commitment"))?;
    let nbits = u32::from_str_radix(&bits, 16).map_err(|_| TemplateError::Missing("bits"))?;
    let prev_hash = ratum::header::u256_from_display_hex(&prev_hash_hex)
        .ok_or(TemplateError::Missing("previousblockhash"))?;

    let list = v["transactions"].as_array().ok_or(TemplateError::Missing("transactions"))?;
    if list.len() > MAX_TXNS {
        return Err(TemplateError::TooManyTxns);
    }
    let mut txns = Vec::with_capacity(list.len());
    let (mut total_fee, mut total_weight, mut total_size, mut total_sigops) =
        (0u64, 0u64, 0u64, 0u64);
    for t in list {
        let txid = ratum::header::u256_from_display_hex(str_field(t, "txid", 64..=64)?)
            .ok_or(TemplateError::Missing("txid"))?;
        let hash = ratum::header::u256_from_display_hex(str_field(t, "hash", 64..=64)?)
            .ok_or(TemplateError::Missing("hash"))?;
        let fee = match t["fee"].as_i64() {
            Some(f) if f >= 0 => f as u64,
            _ => {
                return Err(TemplateError::Refused(
                    "Missing or unknown fee in a GBT transaction; the coinbase value cannot be derived without it".into(),
                ));
            }
        };
        let sigops = t["sigops"].as_u64().unwrap_or(0);
        let weight = t["weight"].as_u64().unwrap_or(0);
        let raw = hex::decode(t["data"].as_str().ok_or(TemplateError::Missing("data"))?)
            .map_err(|_| TemplateError::Missing("data"))?;
        total_fee += fee;
        total_weight += weight;
        total_size += raw.len() as u64;
        total_sigops += sigops;
        txns.push(Txn { raw, txid, hash });
    }

    Ok(Template {
        height,
        coinbase_value,
        txn_total_fee: total_fee,
        mintime,
        curtime,
        sizelimit,
        weightlimit,
        sigoplimit,
        version,
        nbits_bytes: nbits.to_le_bytes(),
        bits,
        nbits,
        prev_hash_hex,
        prev_hash,
        target_hex,
        witness_commitment,
        reduced_data,
        txns,
        txn_total_weight: total_weight as u32,
        txn_total_size: total_size as u32,
        txn_total_sigops: total_sigops as u32,
    })
}

pub fn fetch(node: &rpc::Client) -> Result<serde_json::Value, rpc::Error> {
    node.call("getblocktemplate", serde_json::json!([{"rules": ["segwit", "blake2b"]}]))
}

/// A block notification: from the node's `getbestblockhash` poll, the pool's blocknotify, the
/// API's `/NOTIFY`, SIGUSR1, or the gateway's own block submission. The node poll and the
/// gateway's submission carry the hash of the tip they announce, and the template thread
/// drops a notification for the tip it already serves (the C gateway's
/// `new_notify_blockhash` check); the others carry no hash and are always acted on. A
/// rebuild request (the pool connection changed) makes the thread fetch a template once
/// without expecting a new tip.
#[derive(Default)]
pub struct Notify {
    pending: Mutex<Pending>,
    signal: Condvar,
}

#[derive(Default)]
struct Pending {
    /// `Some(hash)` when the source carries the announced tip's hash (display hex), `Some(None)`
    /// for a notification without one, `None` when nothing is pending.
    block: Option<Option<String>>,
    rebuild: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Wake {
    Block(Option<String>),
    Rebuild,
    Timeout,
}

impl Notify {
    /// A block notification whose tip is not known.
    pub fn raise(&self) {
        self.raise_block(None);
    }

    /// A block notification for the tip `hash_hex` (display order).
    pub fn raise_for(&self, hash_hex: &str) {
        self.raise_block(Some(hash_hex.to_string()));
    }

    fn raise_block(&self, hash: Option<String>) {
        let mut p = ratum::lock(&self.pending);
        // A notification without a hash outranks one with: it may announce a different tip.
        p.block = match (p.block.take(), hash) {
            (Some(None), _) | (_, None) => Some(None),
            (_, Some(h)) => Some(Some(h)),
        };
        self.signal.notify_all();
    }

    pub fn rebuild(&self) {
        ratum::lock(&self.pending).rebuild = true;
        self.signal.notify_all();
    }

    /// Wait up to `d` for a signal, clearing what is returned.
    pub fn wait(&self, d: Duration) -> Wake {
        let g = ratum::lock(&self.pending);
        let (mut g, _) = self
            .signal
            .wait_timeout_while(g, d, |p| p.block.is_none() && !p.rebuild)
            .unwrap_or_else(|p| p.into_inner());
        if let Some(hash) = g.block.take() {
            g.rebuild = false;
            Wake::Block(hash)
        } else if g.rebuild {
            g.rebuild = false;
            Wake::Rebuild
        } else {
            Wake::Timeout
        }
    }
}

/// Poll `getbestblockhash` every second and raise `notify` when it changes
/// (`datum_gateway_fallback_notifier`).
pub fn fallback_notifier(node: rpc::Client, notify: Arc<Notify>) {
    let mut last: Option<String> = None;
    loop {
        match node.call("getbestblockhash", serde_json::json!([])) {
            Ok(v) => {
                if let Some(h) = v.as_str() {
                    if last.as_deref().is_some_and(|l| l != h) {
                        debug!("getbestblockhash changed to {h}");
                        notify.raise_for(h);
                    }
                    last = Some(h.to_string());
                }
            }
            Err(e) => debug!("getbestblockhash failed: {e}"),
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// What the template thread reports to the API.
#[derive(Clone, Default)]
pub struct Status {
    pub error: Option<String>,
}

/// The template thread: fetch, parse, hand to `on_template`, sleep `work_update_seconds` or
/// until a notification. `on_template(template, new_block)` builds and publishes jobs.
pub fn run(
    node: rpc::Client,
    config: Arc<Config>,
    notify: Arc<Notify>,
    status: Arc<Mutex<Status>>,
    payout_script: impl Fn() -> Vec<u8>,
    mut on_template: impl FnMut(Arc<Template>, bool),
) {
    let mut announced = Announced::default();
    let mut last_prev: Option<String> = None;
    let mut below_height_reported: Option<u32> = None;
    let interval = Duration::from_secs(config.bitcoind.work_update_seconds);
    let mut was_notified = false;
    let mut notified_at = Instant::now();
    let mut last_block_change: Option<Instant> = None;
    // A rebuild request (the pool connection came or went) takes the new-block path: clean
    // empty work, then the full job, as the C gateway's `notify_othercause` does, so miners
    // abandon work built on the previous payout script.
    let mut force_clean = false;
    // A refused template is reported once per reason (the C gateway logs it on every poll).
    let mut last_refusal: Option<String> = None;
    loop {
        let raw = match fetch(&node) {
            Ok(v) => v,
            Err(e) => {
                ratum::lock(&status).error = Some("Could not fetch new template!".into());
                error!("Could not fetch new template from {}! ({e})", config.bitcoind.rpcurl);
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
        };
        let template = match parse(&raw, &config, &payout_script(), &mut announced) {
            Ok(t) => t,
            Err(TemplateError::Refused(why)) => {
                ratum::lock(&status).error = Some(why.clone());
                if last_refusal.as_deref() != Some(why.as_str()) {
                    error!("template refused: {why}");
                    last_refusal = Some(why);
                } else {
                    debug!("template refused: {why}");
                }
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
            Err(e) => {
                ratum::lock(&status).error = Some(e.to_string());
                error!("{e}");
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
        };
        ratum::lock(&status).error = None;
        last_refusal = None;

        let tip_changed = last_prev.as_deref() != Some(template.prev_hash_hex.as_str());
        let new_block = tip_changed || force_clean;
        force_clean = false;
        if template.height < config.mining.blake2b_activation_height {
            if below_height_reported != Some(template.height) {
                below_height_reported = Some(template.height);
                warn!(
                    "Block {} is below the BLAKE2b activation height ({}); this gateway mines no other proof of work, so no work will be served until the chain reaches it.",
                    template.height, config.mining.blake2b_activation_height
                );
            }
            last_prev = Some(template.prev_hash_hex.clone());
            was_notified = false;
        } else {
            if tip_changed {
                info!("NEW NETWORK BLOCK: {} ({})", template.prev_hash_hex, template.height);
                last_prev = Some(template.prev_hash_hex.clone());
                last_block_change = Some(Instant::now());
                was_notified = false;
            } else if new_block {
                info!("Rebuilding work on block {} with clean jobs", template.height);
            } else if was_notified {
                // The tip a notification announced has not reached the template yet: poll
                // again below without rebuilding the job on an unchanged template.
                std::thread::sleep(Duration::from_millis(250));
                if notified_at.elapsed() > Duration::from_secs(4) {
                    warn!(
                        "We received a new block notification, however after 16 attempts we did not see a new block."
                    );
                    was_notified = false;
                }
                continue;
            }
            let t = Arc::new(template);
            if new_block {
                info!(
                    "Updating priority stratum job for block {}: {:.8} BTC, {} txns, {} bytes",
                    t.height,
                    t.coinbase_value as f64 / 1e8,
                    t.txns.len(),
                    t.txn_total_size
                );
            } else {
                info!(
                    "Updating standard stratum job for block {}: {:.8} BTC, {} txns, {} bytes",
                    t.height,
                    t.coinbase_value as f64 / 1e8,
                    t.txns.len(),
                    t.txn_total_size
                );
            }
            on_template(t, new_block);
        }

        match notify.wait(interval) {
            // A notification naming the tip already served, or any notification within
            // 2.5 s of a block change, is the same block announced again (the node's poll,
            // the pool, and the gateway's own submission each raise one).
            Wake::Block(Some(hash)) if last_prev.as_deref() == Some(hash.as_str()) => {
                debug!("block notification for the tip already served ({hash}); ignored");
            }
            Wake::Block(_)
                if last_block_change.is_some_and(|t| t.elapsed() < Duration::from_millis(2500)) =>
            {
                debug!("block notification within 2.5 s of the last block change; ignored");
            }
            Wake::Block(_) => {
                info!("NEW NETWORK BLOCK NOTIFICATION RECEIVED");
                was_notified = true;
                notified_at = Instant::now();
            }
            Wake::Rebuild => {
                debug!("Urgent work update triggered");
                force_clean = true;
            }
            Wake::Timeout => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config::parse(
            r#"{
              "bitcoind": {"rpcuser":"u","rpcpassword":"p","rpcurl":"http://127.0.0.1:1"},
              "mining": {"pool_address":"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                         "blake2b_activation_height": 20, "blake2b_headline": "Catbus"},
              "datum": {"pool_host": "", "pooled_mining_only": false}
            }"#,
        )
        .unwrap()
    }

    fn gbt(height: u64, rules: &[&str], headline: Option<&str>) -> serde_json::Value {
        let mut v = serde_json::json!({
            "height": height,
            "coinbasevalue": 5000000000u64,
            "mintime": 1700000000u64,
            "sigoplimit": 80000,
            "curtime": 1700000100u64,
            "sizelimit": 4000000,
            "weightlimit": 4000000,
            "version": 536870912,
            "bits": "207fffff",
            "previousblockhash": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
            "target": "7fffff0000000000000000000000000000000000000000000000000000000000",
            "default_witness_commitment": "6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9",
            "rules": rules,
            "transactions": [],
        });
        if let Some(h) = headline {
            v["coinbaseaux"] = serde_json::json!({"blake2b_headline": hex::encode(h)});
        }
        v
    }

    #[test]
    fn notifications_carry_their_tip_and_an_unknown_tip_outranks_a_known_one() {
        let n = Notify::default();
        assert_eq!(n.wait(Duration::from_millis(1)), Wake::Timeout);
        n.raise_for("aa");
        assert_eq!(n.wait(Duration::from_millis(1)), Wake::Block(Some("aa".into())));
        n.raise_for("aa");
        n.raise();
        n.raise_for("bb");
        assert_eq!(n.wait(Duration::from_millis(1)), Wake::Block(None));
        n.rebuild();
        assert_eq!(n.wait(Duration::from_millis(1)), Wake::Rebuild);
        assert_eq!(n.wait(Duration::from_millis(1)), Wake::Timeout);
    }

    #[test]
    fn parses_an_activation_template() {
        let mut a = Announced::default();
        let t =
            parse(&gbt(20, &["segwit", "!blake2b"], Some("Catbus")), &config(), &[0; 22], &mut a)
                .unwrap();
        assert_eq!(t.height, 20);
        assert_eq!(t.nbits, 0x207fffff);
        assert_eq!(t.nbits_bytes, [0xff, 0xff, 0x7f, 0x20]);
        assert_eq!(t.prev_hash[31], 0x0f);
        assert_eq!(t.witness_commitment.len(), 38);
    }

    #[test]
    fn refuses_a_wrong_headline_and_a_rule_mismatch() {
        let mut a = Announced::default();
        let e =
            parse(&gbt(20, &["segwit", "!blake2b"], Some("Totoro")), &config(), &[0; 22], &mut a);
        assert!(matches!(e, Err(TemplateError::Refused(_))));
        let e = parse(&gbt(21, &["segwit"], None), &config(), &[0; 22], &mut a);
        assert!(matches!(e, Err(TemplateError::Refused(_))));
        let e = parse(&gbt(19, &["segwit", "!blake2b"], None), &config(), &[0; 22], &mut a);
        assert!(matches!(e, Err(TemplateError::Refused(_))));
        assert!(parse(&gbt(19, &["segwit"], None), &config(), &[0; 22], &mut a).is_ok());
    }

    #[test]
    fn reduced_data_refuses_an_oversized_payout_script() {
        let mut a = Announced::default();
        let v = gbt(21, &["segwit", "!blake2b", "reduced_data"], None);
        assert!(parse(&v, &config(), &[0; 35], &mut a).is_err());
        assert!(parse(&v, &config(), &[0; 34], &mut a).is_ok());
    }
}
