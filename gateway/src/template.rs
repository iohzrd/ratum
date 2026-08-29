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
    /// The witness hash (GBT `hash`) in internal byte order: what the short transaction
    /// list identifies transactions by, distinct from `txid`, which the merkle root commits to.
    pub witness_hash: [u8; 32],
}

/// The sums over the template's transactions, which the job section carries.
#[derive(Clone, Copy, Debug, Default)]
pub struct TxnTotals {
    pub fee: u64,
    pub weight: u32,
    pub size: u32,
    pub sigops: u32,
}

#[derive(Clone, Debug)]
pub struct Template {
    pub height: u32,
    pub coinbase_value: u64,
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
    pub totals: TxnTotals,
}

impl Template {
    pub fn witness_hashes(&self) -> Vec<[u8; 32]> {
        self.txns.iter().map(|t| t.witness_hash).collect()
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

fn hash_field(v: &serde_json::Value, key: &'static str) -> Result<[u8; 32], TemplateError> {
    ratum::header::u256_from_display_hex(str_field(v, key, 64..=64)?)
        .ok_or(TemplateError::Missing(key))
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
    let reduced_data = check_rules(v, config, payout_script, announced)?;
    decode(v, reduced_data)
}

/// The consensus checks: the BLAKE2b headline the node will enforce at the activation block,
/// the `!blake2b` rule against the configured activation height, and the payout script
/// against the `reduced_data` rule. Returns whether `reduced_data` is in force.
fn check_rules(
    v: &serde_json::Value,
    config: &Config,
    payout_script: &[u8],
    announced: &mut Announced,
) -> Result<bool, TemplateError> {
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
    Ok(reduced_data)
}

/// The template's fields and transactions, as the JSON carries them.
fn decode(v: &serde_json::Value, reduced_data: bool) -> Result<Template, TemplateError> {
    let height = u64_field(v, "height")? as u32;
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
    let prev_hash = hash_field(v, "previousblockhash")?;

    let list = v["transactions"].as_array().ok_or(TemplateError::Missing("transactions"))?;
    if list.len() > MAX_TXNS {
        return Err(TemplateError::TooManyTxns);
    }
    let mut txns = Vec::with_capacity(list.len());
    let (mut fee, mut weight, mut size, mut sigops) = (0u64, 0u64, 0u64, 0u64);
    for t in list {
        let txid = hash_field(t, "txid")?;
        let witness_hash = hash_field(t, "hash")?;
        match t["fee"].as_i64() {
            Some(f) if f >= 0 => fee += f as u64,
            _ => {
                return Err(TemplateError::Refused(
                    "Missing or unknown fee in a GBT transaction; the coinbase value cannot be derived without it".into(),
                ));
            }
        }
        sigops += t["sigops"].as_u64().unwrap_or(0);
        weight += t["weight"].as_u64().unwrap_or(0);
        let raw = hex::decode(t["data"].as_str().ok_or(TemplateError::Missing("data"))?)
            .map_err(|_| TemplateError::Missing("data"))?;
        size += raw.len() as u64;
        txns.push(Txn { raw, txid, witness_hash });
    }

    Ok(Template {
        height,
        coinbase_value,
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
        totals: TxnTotals { fee, weight: weight as u32, size: size as u32, sigops: sigops as u32 },
    })
}

pub fn fetch(node: &rpc::Client) -> Result<serde_json::Value, rpc::Error> {
    node.call("getblocktemplate", serde_json::json!([{"rules": ["segwit", "blake2b"]}]))
}

/// A block notification: from the node's `getbestblockhash` poll, the pool's blocknotify, the
/// API's `/NOTIFY`, or the gateway's own block submission. The node poll and the
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

/// How long after a block notification the thread polls for the announced tip before it
/// stops expecting one.
const NOTIFY_PATIENCE: Duration = Duration::from_secs(4);
/// A notification within this long of a block change is that block announced again.
const REPEAT_WINDOW: Duration = Duration::from_millis(2500);

/// What the poller does with a template.
#[derive(Debug, PartialEq, Eq)]
enum Action {
    /// Build jobs; with `new_block` the empty job first, with `clean_jobs`.
    Build { new_block: bool },
    /// Below the activation height: no work.
    Skip,
    /// The tip a notification announced has not reached the template: poll again shortly.
    Retry,
}

/// The template thread's state across polls (`datum_gateway_template_thread`).
struct Poller {
    config: Arc<Config>,
    status: Arc<Mutex<Status>>,
    announced: Announced,
    last_prev: Option<String>,
    below_height_reported: Option<u32>,
    was_notified: bool,
    notified_at: Instant,
    last_block_change: Option<Instant>,
    /// A rebuild request (the pool connection came or went) is handled as a new block: clean
    /// empty work, then the full job, as the C gateway's `notify_othercause` does, so miners
    /// abandon work built on the previous payout script.
    force_clean: bool,
    /// A refused template is reported once per reason (the C gateway logs it on every poll).
    last_refusal: Option<String>,
}

impl Poller {
    /// Fetch and parse a template, or the reason there is none, which is reported and
    /// recorded in the status.
    fn poll(&mut self, node: &rpc::Client, payout_script: &[u8]) -> Option<Template> {
        let raw = match fetch(node) {
            Ok(v) => v,
            Err(e) => {
                ratum::lock(&self.status).error = Some("Could not fetch new template!".into());
                error!("Could not fetch new template from {}! ({e})", self.config.bitcoind.rpcurl);
                return None;
            }
        };
        match parse(&raw, &self.config, payout_script, &mut self.announced) {
            Ok(t) => {
                ratum::lock(&self.status).error = None;
                self.last_refusal = None;
                Some(t)
            }
            Err(TemplateError::Refused(why)) => {
                ratum::lock(&self.status).error = Some(why.clone());
                if self.last_refusal.as_deref() != Some(why.as_str()) {
                    error!("template refused: {why}");
                    self.last_refusal = Some(why);
                } else {
                    debug!("template refused: {why}");
                }
                None
            }
            Err(e) => {
                ratum::lock(&self.status).error = Some(e.to_string());
                error!("{e}");
                None
            }
        }
    }

    /// What to do with a template the node returned.
    fn classify(&mut self, template: &Template) -> Action {
        let tip_changed = self.last_prev.as_deref() != Some(template.prev_hash_hex.as_str());
        let new_block = tip_changed || self.force_clean;
        self.force_clean = false;
        let activation = self.config.mining.blake2b_activation_height;
        if template.height < activation {
            if self.below_height_reported != Some(template.height) {
                self.below_height_reported = Some(template.height);
                warn!(
                    "Block {} is below the BLAKE2b activation height ({activation}); this gateway mines no other proof of work, so no work will be served until the chain reaches it.",
                    template.height
                );
            }
            self.last_prev = Some(template.prev_hash_hex.clone());
            self.was_notified = false;
            return Action::Skip;
        }
        if tip_changed {
            info!("NEW NETWORK BLOCK: {} ({})", template.prev_hash_hex, template.height);
            self.last_prev = Some(template.prev_hash_hex.clone());
            self.last_block_change = Some(Instant::now());
            self.was_notified = false;
        } else if new_block {
            info!("Rebuilding work on block {} with clean jobs", template.height);
        } else if self.was_notified {
            if self.notified_at.elapsed() > NOTIFY_PATIENCE {
                warn!(
                    "We received a new block notification, however after 16 attempts we did not see a new block."
                );
                self.was_notified = false;
            }
            return Action::Retry;
        }
        Action::Build { new_block }
    }

    /// Act on what `notify` delivered while waiting.
    fn on_wake(&mut self, wake: Wake) {
        match wake {
            // A notification naming the tip already served, or any notification within
            // `REPEAT_WINDOW` of a block change, is the same block announced again (the
            // node's poll, the pool, and the gateway's own submission each raise one).
            Wake::Block(Some(hash)) if self.last_prev.as_deref() == Some(hash.as_str()) => {
                debug!("block notification for the tip already served ({hash}); ignored");
            }
            Wake::Block(_)
                if self.last_block_change.is_some_and(|t| t.elapsed() < REPEAT_WINDOW) =>
            {
                debug!("block notification within 2.5 s of the last block change; ignored");
            }
            Wake::Block(_) => {
                info!("NEW NETWORK BLOCK NOTIFICATION RECEIVED");
                self.was_notified = true;
                self.notified_at = Instant::now();
            }
            Wake::Rebuild => {
                debug!("Urgent work update triggered");
                self.force_clean = true;
            }
            Wake::Timeout => {}
        }
    }
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
    let interval = Duration::from_secs(config.bitcoind.work_update_seconds);
    let mut p = Poller {
        config,
        status,
        announced: Announced::default(),
        last_prev: None,
        below_height_reported: None,
        was_notified: false,
        notified_at: Instant::now(),
        last_block_change: None,
        force_clean: false,
        last_refusal: None,
    };
    loop {
        let Some(template) = p.poll(&node, &payout_script()) else {
            std::thread::sleep(Duration::from_secs(1));
            continue;
        };
        match p.classify(&template) {
            Action::Skip => {}
            Action::Retry => {
                std::thread::sleep(Duration::from_millis(250));
                continue;
            }
            Action::Build { new_block } => {
                let t = Arc::new(template);
                info!(
                    "Updating {} stratum job for block {}: {:.8} BTC, {} txns, {} bytes",
                    if new_block { "priority" } else { "standard" },
                    t.height,
                    t.coinbase_value as f64 / 1e8,
                    t.txns.len(),
                    t.totals.size
                );
                on_template(t, new_block);
            }
        }
        p.on_wake(notify.wait(interval));
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A configuration with the required keys, non-pooled, six job slots.
    pub(crate) fn config() -> Config {
        Config::parse(
            r#"{
              "bitcoind": {"rpcuser":"u","rpcpassword":"p","rpcurl":"http://127.0.0.1:1"},
              "mining": {"pool_address":"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                         "blake2b_activation_height": 20, "blake2b_headline": "Catbus"},
              "datum": {"pool_host": "", "pooled_mining_only": false, "protocol_job_slots": 6}
            }"#,
        )
        .unwrap()
    }

    /// A regtest template at height 21 with no transactions.
    pub(crate) fn template() -> Template {
        let mut wc = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        wc.extend_from_slice(&[0u8; 32]);
        Template {
            height: 21,
            coinbase_value: 5_000_000_000,
            mintime: 1_700_000_000,
            curtime: 1_700_000_100,
            sizelimit: 4_000_000,
            weightlimit: 4_000_000,
            sigoplimit: 80_000,
            version: 0x2000_0000,
            bits: "207fffff".into(),
            nbits: 0x207f_ffff,
            nbits_bytes: [0xff, 0xff, 0x7f, 0x20],
            prev_hash_hex: "00".repeat(32),
            prev_hash: [0u8; 32],
            target_hex: "7f".repeat(32),
            witness_commitment: wc,
            reduced_data: false,
            txns: vec![],
            totals: TxnTotals::default(),
        }
    }

    /// A non-pooled job on `template()` whose id is `job_id`.
    pub(crate) fn job_with_id(job_id: &str) -> crate::job::Job {
        let mut b = crate::job::Builder::new(Arc::new(config()));
        let mut job = b.build(Arc::new(template()), false, None, None).unwrap();
        job.job_id = job_id.to_string();
        job
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
    fn decodes_transactions_without_the_rule_checks() {
        let mut v = gbt(21, &[], None);
        v["transactions"] = serde_json::json!([{
            "txid": "11".repeat(32), "hash": "22".repeat(32), "fee": 1000, "sigops": 4,
            "weight": 400, "data": "0100",
        }]);
        let t = decode(&v, true).unwrap();
        assert!(t.reduced_data);
        assert_eq!(t.txns.len(), 1);
        assert_eq!(t.totals.fee, 1000);
        assert_eq!(t.totals.sigops, 4);
        assert_eq!(t.totals.weight, 400);
        assert_eq!(t.totals.size, 2);
        v["transactions"][0]["fee"] = serde_json::json!(-1);
        assert!(matches!(decode(&v, false), Err(TemplateError::Refused(_))));
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

    fn poller() -> Poller {
        Poller {
            config: Arc::new(config()),
            status: Arc::new(Mutex::new(Status::default())),
            announced: Announced::default(),
            last_prev: None,
            below_height_reported: None,
            was_notified: false,
            notified_at: Instant::now(),
            last_block_change: None,
            force_clean: false,
            last_refusal: None,
        }
    }

    #[test]
    fn a_new_tip_builds_clean_and_the_same_tip_builds_standard() {
        let mut p = poller();
        let t = template();
        assert_eq!(p.classify(&t), Action::Build { new_block: true });
        assert_eq!(p.classify(&t), Action::Build { new_block: false });
        p.on_wake(Wake::Rebuild);
        assert_eq!(p.classify(&t), Action::Build { new_block: true }, "a rebuild is clean");
        let mut below = template();
        below.height = 19;
        assert_eq!(p.classify(&below), Action::Skip);
    }

    #[test]
    fn a_notification_for_an_unseen_tip_retries_until_it_arrives_or_expires() {
        let mut p = poller();
        let t = template();
        p.classify(&t);
        p.on_wake(Wake::Block(Some(t.prev_hash_hex.clone())));
        assert_eq!(p.classify(&t), Action::Build { new_block: false }, "the tip served: ignored");
        p.last_block_change = Some(Instant::now() - Duration::from_secs(10));
        p.on_wake(Wake::Block(None));
        assert_eq!(p.classify(&t), Action::Retry);
        p.notified_at = Instant::now() - NOTIFY_PATIENCE - Duration::from_secs(1);
        assert_eq!(
            p.classify(&t),
            Action::Retry,
            "the attempt at which patience ends still retries"
        );
        assert_eq!(p.classify(&t), Action::Build { new_block: false });
        let mut next = template();
        next.prev_hash_hex = "11".repeat(32);
        p.on_wake(Wake::Block(None));
        assert_eq!(p.classify(&next), Action::Build { new_block: true });
        p.on_wake(Wake::Block(None));
        assert_eq!(p.classify(&next), Action::Build { new_block: false }, "within 2.5 s: ignored");
    }
}
