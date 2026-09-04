//! The configuration file: the same JSON schema as the C gateway's `datum_gateway_config.json`,
//! so a deployment can swap the binary without changing its file. Every key is optional
//! except the ones the C gateway requires (`bitcoind.rpcurl`, `mining.pool_address`).
//! Unknown keys are ignored, as the C gateway ignores them. The second half is the settings
//! page's editing of the file (`apply`, `write_file`, `restart`).

use serde::Deserialize;
use serde_json::{Value, json};

/// Jobs a new tip builds beyond the one the C gateway's slot check counts: the empty job and
/// the priority job before the coinbaser job.
const EXTRA_JOBS_PER_TIP: u64 = 2;

fn t() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Bitcoind {
    pub rpccookiefile: String,
    pub rpcuser: String,
    pub rpcpassword: String,
    pub rpcurl: String,
    pub work_update_seconds: u64,
    #[serde(default = "t")]
    pub notify_fallback: bool,
}

impl Default for Bitcoind {
    fn default() -> Self {
        Bitcoind {
            rpccookiefile: String::new(),
            rpcuser: String::new(),
            rpcpassword: String::new(),
            rpcurl: String::new(),
            work_update_seconds: 40,
            notify_fallback: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Stratum {
    pub listen_addr: String,
    pub listen_port: u16,
    pub max_clients_per_thread: usize,
    pub max_threads: usize,
    pub max_clients: usize,
    pub trust_proxy: i64,
    pub vardiff_min: u64,
    pub vardiff_target_shares_min: u64,
    pub vardiff_quickdiff_count: u64,
    pub vardiff_quickdiff_delta: u64,
    pub share_stale_seconds: u64,
    pub fingerprint_miners: bool,
    pub idle_timeout_no_subscribe: u64,
    pub idle_timeout_no_shares: u64,
    pub idle_timeout_max_last_work: u64,
    pub require_address_username: bool,
    /// `{"modname": {"address": proportion, ...}}`; an empty address keeps the miner's own.
    /// The ranges are in the file's order, as `json_object_foreach` walks them in C: the
    /// first address takes the low hash values.
    #[serde(deserialize_with = "deserialize_modifiers")]
    pub username_modifiers: crate::username::Modifiers,
}

/// A JSON object read into pairs in document order, which `serde_json`'s map types do not
/// keep.
pub struct Ordered<V>(pub Vec<(String, V)>);

impl<'de, V: Deserialize<'de>> Deserialize<'de> for Ordered<V> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::{MapAccess, Visitor};
        use std::marker::PhantomData;

        struct Pairs<V>(PhantomData<V>);
        impl<'de, V: Deserialize<'de>> Visitor<'de> for Pairs<V> {
            type Value = Ordered<V>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Self::Value, A::Error> {
                let mut v = Vec::new();
                while let Some(pair) = m.next_entry::<String, V>()? {
                    v.push(pair);
                }
                Ok(Ordered(v))
            }
        }
        d.deserialize_map(Pairs(PhantomData))
    }
}

/// `stratum.username_modifiers`: an object of objects, both levels in document order.
fn deserialize_modifiers<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<crate::username::Modifiers, D::Error> {
    let mods = Ordered::<Ordered<f64>>::deserialize(d)?;
    Ok(mods.0.into_iter().map(|(name, ranges)| (name, ranges.0)).collect())
}

impl Default for Stratum {
    fn default() -> Self {
        Stratum {
            listen_addr: String::new(),
            listen_port: 23334,
            max_clients_per_thread: 128,
            max_threads: 8,
            max_clients: 1024,
            trust_proxy: -1,
            vardiff_min: 16384,
            vardiff_target_shares_min: 8,
            vardiff_quickdiff_count: 8,
            vardiff_quickdiff_delta: 8,
            share_stale_seconds: 120,
            fingerprint_miners: true,
            idle_timeout_no_subscribe: 15,
            idle_timeout_no_shares: 7200,
            idle_timeout_max_last_work: 0,
            require_address_username: false,
            username_modifiers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Mining {
    pub pool_address: String,
    pub coinbase_tag_primary: String,
    pub coinbase_tag_secondary: String,
    pub coinbase_unique_id: u32,
    pub save_submitblocks_dir: String,
}

impl Default for Mining {
    fn default() -> Self {
        Mining {
            pool_address: String::new(),
            coinbase_tag_primary: "DATUM Gateway".into(),
            coinbase_tag_secondary: "DATUM User".into(),
            coinbase_unique_id: 4242,
            save_submitblocks_dir: String::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Api {
    pub admin_password: String,
    pub allow_insecure_auth: bool,
    pub listen_addr: String,
    pub listen_port: u16,
    pub miner_listen_addr: String,
    /// The password-less miner lookup page; 0 disables it.
    pub miner_listen_port: u16,
    pub modify_conf: bool,
}

impl Default for Api {
    fn default() -> Self {
        Self {
            admin_password: String::new(),
            allow_insecure_auth: false,
            listen_addr: String::new(),
            listen_port: 0,
            miner_listen_addr: String::new(),
            miner_listen_port: 8000,
            modify_conf: false,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ExtraBlockSubmissions {
    pub urls: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Logger {
    pub log_to_console: bool,
    pub log_to_stderr: bool,
    pub log_to_file: bool,
    pub log_file: String,
    /// Accepted for the C gateway's file and not applied: `Some` when the file sets it.
    pub log_rotate_daily: Option<bool>,
    pub log_calling_function: bool,
    pub log_level_console: u8,
    pub log_level_file: u8,
}

impl Default for Logger {
    fn default() -> Self {
        Logger {
            log_to_console: true,
            log_to_stderr: false,
            log_to_file: false,
            log_file: String::new(),
            log_rotate_daily: None,
            log_calling_function: true,
            log_level_console: 2,
            log_level_file: 1,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Datum {
    pub pool_host: String,
    pub pool_port: u16,
    /// The pool's web page (`https://pool.example`), which the status and miner pages link
    /// the pool to when it is set. Not a C gateway key; the DATUM host need not serve a page.
    pub pool_url: String,
    pub pool_pubkey: String,
    pub pool_pass_workers: bool,
    pub protocol_job_slots: usize,
    pub pool_pass_full_users: bool,
    pub gateway_fee_bps: u32,
    pub gateway_fee_address: String,
    /// Accepted for the C gateway's file and not applied: `Some` when the file sets it.
    pub always_pay_self: Option<bool>,
    pub pooled_mining_only: bool,
    pub protocol_global_timeout: u64,
    /// Use the version 3 protocol to the pool: the DRS hello, version 3 config, and
    /// anti-block-withholding. On by default. A version 1 pool reads the DRS extension as
    /// hello padding and responds with a version 1 configuration, which the gateway accepts;
    /// that session runs the version 1 protocol. Under version 3 the gateway commits its work
    /// to the pool's ABW assignment and does not classify or submit blocks itself; the pool
    /// holds the XOR key and submits them. Off sends a version 1 hello.
    pub protocol_v3: bool,
}

impl Default for Datum {
    fn default() -> Self {
        Datum {
            pool_host: "datum-beta1.mine.ocean.xyz".into(),
            pool_port: 28915,
            pool_url: String::new(),
            pool_pubkey: "f21f2f0ef0aa1970468f22bad9bb7f4535146f8e4a8f646bebc93da3d89b1406f40d032f09a417d94dc068055df654937922d2c89522e3e8f6f0e649de473003".into(),
            pool_pass_workers: true,
            protocol_job_slots: 256,
            pool_pass_full_users: true,
            gateway_fee_bps: 0,
            gateway_fee_address: String::new(),
            always_pay_self: None,
            pooled_mining_only: true,
            protocol_global_timeout: 60,
            protocol_v3: true,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub bitcoind: Bitcoind,
    pub stratum: Stratum,
    pub mining: Mining,
    pub api: Api,
    pub extra_block_submissions: ExtraBlockSubmissions,
    pub logger: Logger,
    pub datum: Datum,
    /// What `validate` has to say that is not an error: logged by `main` once the logger the
    /// file configures exists, since the file is parsed before it can.
    #[serde(skip)]
    pub warnings: Vec<(log::Level, String)>,
    /// The output script `mining.pool_address` pays to, decoded once by `validate`.
    #[serde(skip)]
    pub pool_output_script: Vec<u8>,
}

/// The largest coinbase tag space: what fits in a 100-byte scriptSig beside the height push,
/// the unique-id push and the extranonce push.
pub const MAX_COINBASE_TAG_SPACE: usize = 86;

impl Config {
    pub fn parse(text: &str) -> Result<Config, String> {
        let mut c: Config = serde_json::from_str(text).map_err(|e| e.to_string())?;
        c.validate()?;
        Ok(c)
    }

    /// The C gateway's post-parse checks (`datum_read_config`), with the same outcomes: a
    /// clamped value is clamped, a refused one is an error naming the key.
    fn validate(&mut self) -> Result<(), String> {
        self.validate_bitcoind()?;
        self.validate_stratum()?;
        self.validate_mining()?;
        self.validate_api();
        self.validate_datum()?;
        self.validate_username_modifiers()
    }

    fn warn(&mut self, message: impl Into<String>) {
        self.warnings.push((log::Level::Warn, message.into()));
    }

    fn validate_bitcoind(&mut self) -> Result<(), String> {
        if self.bitcoind.rpcurl.is_empty() {
            return Err("Required configuration option (bitcoind.rpcurl) not found".into());
        }
        if !self.bitcoind.rpcuser.is_empty() {
            if self.bitcoind.rpcpassword.is_empty() {
                return Err("bitcoind.rpcpassword is required with bitcoind.rpcuser".into());
            }
        } else if self.bitcoind.rpccookiefile.is_empty() {
            return Err("Either bitcoind.rpcuser (and bitcoind.rpcpassword) or bitcoind.rpccookiefile is required.".into());
        }
        self.bitcoind.work_update_seconds = self.bitcoind.work_update_seconds.clamp(5, 120);
        Ok(())
    }

    fn validate_stratum(&mut self) -> Result<(), String> {
        let s = &self.stratum;
        if s.max_threads > 64 {
            return Err("stratum.max_threads must be at most 64".into());
        }
        if s.max_clients_per_thread > 4096 {
            return Err("stratum.max_clients_per_thread must be at most 4096".into());
        }
        if s.max_clients > s.max_clients_per_thread * s.max_threads {
            return Err("stratum.max_clients exceeds max_clients_per_thread * max_threads".into());
        }
        if s.vardiff_min == 0 {
            return Err("stratum.vardiff_min must be at least 1".into());
        }
        if s.vardiff_target_shares_min < 1 {
            return Err("stratum.vardiff_target_shares_min must be at least 1".into());
        }
        if s.vardiff_quickdiff_count < 4 {
            return Err("stratum.vardiff_quickdiff_count must be at least 4".into());
        }
        if s.vardiff_quickdiff_delta < 3 {
            return Err("stratum.vardiff_quickdiff_delta must be at least 3".into());
        }
        if !(60..=150).contains(&s.share_stale_seconds) {
            return Err("stratum.share_stale_seconds must be 60..150".into());
        }
        if !s.vardiff_min.is_power_of_two() {
            let rounded = ratum::target::pow2_floor(s.vardiff_min);
            let was = s.vardiff_min;
            self.stratum.vardiff_min = rounded;
            self.warn(format!("stratum.vardiff_min {was} is not a power of two; using {rounded}"));
        }
        if self.stratum.trust_proxy != -1 {
            self.warn("stratum.trust_proxy is set but the PROXY protocol is not supported; a connection that sends a PROXY line is closed");
        }
        Ok(())
    }

    fn validate_mining(&mut self) -> Result<(), String> {
        let m = &self.mining;
        if m.pool_address.is_empty() {
            return Err("Required configuration option (mining.pool_address) not found".into());
        }
        let tags = m.coinbase_tag_primary.len() + m.coinbase_tag_secondary.len();
        if tags > 88 || m.coinbase_tag_primary.len() > 60 || m.coinbase_tag_secondary.len() > 60 {
            return Err("mining.coinbase_tag_primary and mining.coinbase_tag_secondary must be at most 60 bytes each and 88 bytes together".into());
        }
        self.pool_output_script = crate::address::to_output_script(&m.pool_address)
            .ok_or("mining.pool_address is not an address a coinbase output can pay")?;
        Ok(())
    }

    fn validate_api(&mut self) {
        if self.api.allow_insecure_auth {
            self.warn(
                "api.allow_insecure_auth has no effect: the API uses HTTP Basic authentication",
            );
        }
        if self.api.modify_conf && self.api.admin_password.is_empty() {
            self.warn("api.modify_conf is set but api.admin_password is empty, so the settings page cannot save");
        }
        if self.logger.log_rotate_daily.is_some() {
            self.warn("logger.log_rotate_daily has no effect: the file is held open, so rotate it with logrotate's copytruncate");
        }
    }

    fn validate_datum(&mut self) -> Result<(), String> {
        let d = &self.datum;
        if !(1..=256).contains(&d.protocol_job_slots) {
            return Err("datum.protocol_job_slots must be 1..256".into());
        }
        // The C gateway's check counts one job per work update. A new tip builds three jobs
        // here (empty, priority, coinbaser) where C builds one and rewrites its coinbase, so
        // two slots are reserved for them.
        let min_slots = EXTRA_JOBS_PER_TIP
            + (self.stratum.share_stale_seconds + self.bitcoind.work_update_seconds)
                .div_ceil(self.bitcoind.work_update_seconds);
        if (d.protocol_job_slots as u64) < min_slots {
            return Err(format!(
                "datum.protocol_job_slots must be at least {min_slots} for stratum.share_stale_seconds {} and bitcoind.work_update_seconds {}",
                self.stratum.share_stale_seconds, self.bitcoind.work_update_seconds
            ));
        }
        if d.protocol_global_timeout < self.bitcoind.work_update_seconds + 5 {
            return Err(
                "datum.protocol_global_timeout must be at least bitcoind.work_update_seconds + 5"
                    .into(),
            );
        }
        if d.pooled_mining_only && d.pool_host.is_empty() {
            return Err("datum.pooled_mining_only requires datum.pool_host".into());
        }
        if d.gateway_fee_bps > 10000 {
            return Err("datum.gateway_fee_bps must be 0..10000".into());
        }
        if d.gateway_fee_bps > 0 {
            if !d.pool_pass_full_users {
                return Err("datum.gateway_fee_bps requires datum.pool_pass_full_users, since a fee share is credited to the fee address in place of the miner's own username".into());
            }
            if !d.gateway_fee_address.is_empty()
                && !crate::address::is_valid(&d.gateway_fee_address)
            {
                return Err(
                    "datum.gateway_fee_address is not an address a coinbase output can pay".into(),
                );
            }
        }
        if !d.pool_host.is_empty() {
            crate::datum::parse_pool_pubkey(&d.pool_pubkey)
                .map_err(|e| format!("datum.pool_pubkey: {e}"))?;
        }
        if d.gateway_fee_bps > 0 && d.pool_host.is_empty() {
            self.warn("datum.gateway_fee_bps is set but datum.pool_host is empty; a fee applies only to pooled shares");
        }
        if self.stratum.require_address_username && !self.datum.pool_pass_full_users {
            self.warn("stratum.require_address_username is set but datum.pool_pass_full_users is not, so the pool never receives the address the username was checked for");
        }
        if self.datum.always_pay_self.is_some() {
            self.warn("datum.always_pay_self has no effect: the coinbase always pays the pool script the split leaves");
        }
        Ok(())
    }

    fn validate_username_modifiers(&mut self) -> Result<(), String> {
        let mut notes = Vec::new();
        for (modname, ranges) in &self.stratum.username_modifiers {
            let mut sum = 0f64;
            let mut covered = false;
            for (addr, proportion) in ranges.iter() {
                if *proportion < 0.0 {
                    return Err(format!("stratum.username_modifiers.{modname}.{addr} is negative"));
                }
                sum += proportion;
                if (sum * 65536.0).ceil() - 1.0 >= 65535.0 {
                    covered = true;
                    break;
                }
            }
            // The C gateway's `datum_config_parse_username_mods`: shares past the last range
            // go to mining.pool_address, which is reported and not refused.
            if !covered {
                notes.push((
                    log::Level::Error,
                    format!(
                        "Username modifier '{modname}' is configured to not distribute {}% of shares!",
                        100.0 * (1.0 - sum)
                    ),
                ));
            }
        }
        self.warnings.extend(notes);
        Ok(())
    }

    /// The window after a job's creation in which a share on it is accepted.
    pub fn stale_window(&self) -> std::time::Duration {
        std::time::Duration::from_secs(
            self.stratum.share_stale_seconds + self.bitcoind.work_update_seconds,
        )
    }

    /// The most shares one stratum thread's clients send within the stale window, sixteen
    /// times over: the C gateway's sizing of the share queue.
    pub fn share_queue_capacity(&self) -> usize {
        let s = &self.stratum;
        s.max_clients_per_thread
            * s.vardiff_target_shares_min as usize
            * (s.share_stale_seconds / 60) as usize
            * 16
    }

    /// `share_queue_capacity` for every stratum thread: the duplicate-share table's size.
    pub fn dupe_table_capacity(&self) -> usize {
        self.share_queue_capacity() * self.stratum.max_threads
    }

    /// The address fee shares are credited to: `datum.gateway_fee_address`, or the
    /// gateway's own `mining.pool_address` when it is empty.
    pub fn fee_address(&self) -> &str {
        if self.datum.gateway_fee_address.is_empty() {
            &self.mining.pool_address
        } else {
            &self.datum.gateway_fee_address
        }
    }
}

// The settings page (`/config`, `api.modify_conf`). Each form field names one key of the
// file. `apply` puts the submitted values into the file's JSON document, parses the result
// with the startup validation, and returns the text to write; the caller rewrites the file
// and calls `restart`, since every thread holds the configuration it started with. The
// field names and the `pool_host(old)` convention are the C gateway's, so a file either
// gateway edited reads the same in both.

/// One form field that sets one key.
struct Field {
    /// The form field's name, `section_key`.
    name: &'static str,
    /// What an error names.
    label: &'static str,
    section: &'static str,
    key: &'static str,
    kind: Kind,
    /// The value the running gateway uses, which the page shows and an unchanged submission
    /// is compared with.
    current: fn(&Config) -> Value,
}

enum Kind {
    Text,
    /// A whole number in the inclusive range.
    Int(i64, i64),
    /// `1` or `0`.
    Bool,
    /// Never shown; an empty submission keeps the file's value.
    Password,
}

const FIELDS: &[Field] = &[
    Field {
        name: "mining_pool_address",
        label: "Bitcoin address",
        section: "mining",
        key: "pool_address",
        kind: Kind::Text,
        current: |c| json!(c.mining.pool_address),
    },
    Field {
        name: "mining_coinbase_tag_secondary",
        label: "Coinbase tag",
        section: "mining",
        key: "coinbase_tag_secondary",
        kind: Kind::Text,
        current: |c| json!(c.mining.coinbase_tag_secondary),
    },
    Field {
        name: "mining_coinbase_unique_id",
        label: "Unique gateway ID",
        section: "mining",
        key: "coinbase_unique_id",
        kind: Kind::Int(0, 65535),
        current: |c| json!(c.mining.coinbase_unique_id),
    },
    Field {
        name: "datum_pool_port",
        label: "Pool port",
        section: "datum",
        key: "pool_port",
        kind: Kind::Int(1, 65535),
        current: |c| json!(c.datum.pool_port),
    },
    Field {
        name: "datum_pool_pubkey",
        label: "Pool public key",
        section: "datum",
        key: "pool_pubkey",
        kind: Kind::Text,
        current: |c| json!(c.datum.pool_pubkey),
    },
    Field {
        name: "datum_pool_url",
        label: "Pool web page",
        section: "datum",
        key: "pool_url",
        kind: Kind::Text,
        current: |c| json!(c.datum.pool_url),
    },
    Field {
        name: "datum_protocol_v3",
        label: "Version 3 protocol",
        section: "datum",
        key: "protocol_v3",
        kind: Kind::Bool,
        current: |c| json!(c.datum.protocol_v3),
    },
    Field {
        name: "datum_gateway_fee_bps",
        label: "Gateway fee",
        section: "datum",
        key: "gateway_fee_bps",
        kind: Kind::Int(0, 10000),
        current: |c| json!(c.datum.gateway_fee_bps),
    },
    Field {
        name: "datum_gateway_fee_address",
        label: "Gateway fee address",
        section: "datum",
        key: "gateway_fee_address",
        kind: Kind::Text,
        current: |c| json!(c.datum.gateway_fee_address),
    },
    Field {
        name: "stratum_listen_port",
        label: "Stratum port",
        section: "stratum",
        key: "listen_port",
        kind: Kind::Int(1, 65535),
        current: |c| json!(c.stratum.listen_port),
    },
    Field {
        name: "stratum_vardiff_min",
        label: "Minimum difficulty",
        section: "stratum",
        key: "vardiff_min",
        kind: Kind::Int(1, i64::MAX),
        current: |c| json!(c.stratum.vardiff_min),
    },
    Field {
        name: "stratum_fingerprint_miners",
        label: "Fingerprint miners",
        section: "stratum",
        key: "fingerprint_miners",
        kind: Kind::Bool,
        current: |c| json!(c.stratum.fingerprint_miners),
    },
    Field {
        name: "stratum_require_address_username",
        label: "Require an address as the username",
        section: "stratum",
        key: "require_address_username",
        kind: Kind::Bool,
        current: |c| json!(c.stratum.require_address_username),
    },
    Field {
        name: "bitcoind_work_update_seconds",
        label: "Job update interval",
        section: "bitcoind",
        key: "work_update_seconds",
        kind: Kind::Int(5, 120),
        current: |c| json!(c.bitcoind.work_update_seconds),
    },
    Field {
        name: "bitcoind_rpcurl",
        label: "bitcoind RPC URL",
        section: "bitcoind",
        key: "rpcurl",
        kind: Kind::Text,
        current: |c| json!(c.bitcoind.rpcurl),
    },
    Field {
        name: "bitcoind_rpcuser",
        label: "bitcoind RPC user",
        section: "bitcoind",
        key: "rpcuser",
        kind: Kind::Text,
        current: |c| json!(c.bitcoind.rpcuser),
    },
    Field {
        name: "bitcoind_rpcpassword",
        label: "bitcoind RPC password",
        section: "bitcoind",
        key: "rpcpassword",
        kind: Kind::Password,
        current: |_| Value::Null,
    },
];

/// The `datum.pool_host` the page shows: the running one, else the file's `pool_host(old)`
/// (what the C gateway keeps when reward sharing is set to never), else the default.
fn shown_pool_host(cfg: &Config, doc: &Value) -> String {
    if !cfg.datum.pool_host.is_empty() {
        return cfg.datum.pool_host.clone();
    }
    old_pool_host(doc).unwrap_or_else(|| Datum::default().pool_host)
}

fn old_pool_host(doc: &Value) -> Option<String> {
    doc.get("datum")?.get("pool_host(old)")?.as_str().map(str::to_string)
}

/// The largest `mining.coinbase_tag_secondary` beside the running primary tag: what
/// `validate_mining` accepts.
fn secondary_tag_max(cfg: &Config) -> usize {
    (88usize.saturating_sub(cfg.mining.coinbase_tag_primary.len())).min(60)
}

fn username_behaviour(cfg: &Config) -> &'static str {
    if cfg.datum.pool_pass_full_users {
        "full_users"
    } else if cfg.datum.pool_pass_workers {
        "workers"
    } else {
        "private"
    }
}

fn reward_sharing(cfg: &Config) -> &'static str {
    if cfg.datum.pool_host.is_empty() {
        "never"
    } else if cfg.datum.pooled_mining_only {
        "require"
    } else {
        "prefer"
    }
}

/// What the page's form shows, keyed by field name. `doc` is the file's document, or null
/// when it could not be read.
pub fn form_values(cfg: &Config, doc: &Value) -> Value {
    let mut v = serde_json::Map::new();
    for f in FIELDS {
        if !matches!(f.kind, Kind::Password) {
            v.insert(f.name.into(), (f.current)(cfg));
        }
    }
    v.insert("username_behaviour".into(), json!(username_behaviour(cfg)));
    v.insert("reward_sharing".into(), json!(reward_sharing(cfg)));
    v.insert("datum_pool_host".into(), json!(shown_pool_host(cfg, doc)));
    v.insert("mining_coinbase_tag_secondary_max".into(), json!(secondary_tag_max(cfg)));
    Value::Object(v)
}

/// The document's `section` object, created when absent.
fn section<'a>(
    doc: &'a mut Value,
    name: &str,
) -> Result<&'a mut serde_json::Map<String, Value>, String> {
    let root = doc.as_object_mut().ok_or("the configuration file is not a JSON object")?;
    let entry = root.entry(name).or_insert_with(|| Value::Object(Default::default()));
    entry.as_object_mut().ok_or_else(|| format!("the file's \"{name}\" is not a JSON object"))
}

/// The edits one submission makes to the document.
struct Edit<'a> {
    doc: &'a mut Value,
    changed: bool,
    errors: Vec<String>,
}

impl Edit<'_> {
    fn set(&mut self, section_name: &str, key: &str, value: Value) {
        match section(self.doc, section_name) {
            Ok(s) => {
                s.insert(key.into(), value);
                self.changed = true;
            }
            Err(e) => self.errors.push(e),
        }
    }

    /// `set` unless the running value is already `value`.
    fn set_if_changed(&mut self, section_name: &str, key: &str, value: Value, current: Value) {
        if value != current {
            self.set(section_name, key, value);
        }
    }

    fn remove(&mut self, section_name: &str, key: &str) {
        if let Some(s) = self.doc.get_mut(section_name).and_then(Value::as_object_mut)
            && s.remove(key).is_some()
        {
            self.changed = true;
        }
    }
}

fn parse_int(label: &str, text: &str, min: i64, max: i64) -> Result<i64, String> {
    let v = text.trim().parse::<i64>().map_err(|_| format!("{label} must be a whole number"))?;
    if v < min || v > max {
        return Err(format!("{label} must be between {min} and {max}"));
    }
    Ok(v)
}

fn parse_bool(label: &str, text: &str) -> Result<bool, String> {
    match text.trim() {
        "1" | "true" | "on" => Ok(true),
        "0" | "false" | "off" | "" => Ok(false),
        _ => Err(format!("{label} must be 1 or 0")),
    }
}

/// The document's text as the file is written: four-space indentation, as the C gateway
/// writes it.
fn render(doc: &Value) -> String {
    let mut out = Vec::new();
    let fmt = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    let mut ser = serde_json::Serializer::with_formatter(&mut out, fmt);
    serde::Serialize::serialize(doc, &mut ser).expect("a Value serializes");
    out.push(b'\n');
    String::from_utf8(out).expect("JSON is UTF-8")
}

/// The file's text with `form`'s edits, validated: `Ok(None)` when no value differs from
/// the running configuration, `Ok(Some(text))` to write, or the errors, in which case
/// nothing is to be written.
pub fn apply(
    cfg: &Config,
    file_text: &str,
    form: &[(String, String)],
) -> Result<Option<String>, Vec<String>> {
    let mut doc: Value = serde_json::from_str(file_text)
        .map_err(|e| vec![format!("the configuration file is not valid JSON: {e}")])?;
    let mut edit = Edit { doc: &mut doc, changed: false, errors: Vec::new() };
    let field = |name: &str| form.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());

    // The reward-sharing choice first: it decides whether the pool host field sets
    // `pool_host` or the parked `pool_host(old)`.
    let mut pool_host = cfg.datum.pool_host.clone();
    let default_host = Datum::default().pool_host;
    match field("reward_sharing") {
        None => {}
        Some(choice @ ("require" | "prefer")) => {
            let only = choice == "require";
            edit.set_if_changed(
                "datum",
                "pooled_mining_only",
                json!(only),
                json!(cfg.datum.pooled_mining_only),
            );
            if pool_host.is_empty() {
                match old_pool_host(edit.doc) {
                    Some(old) => {
                        edit.remove("datum", "pool_host(old)");
                        edit.set("datum", "pool_host", json!(old));
                        pool_host = old;
                    }
                    None => {
                        // Absent, the default applies; the file does not name it, as the C
                        // gateway leaves it out.
                        edit.remove("datum", "pool_host");
                        edit.changed = true;
                        pool_host = default_host.clone();
                    }
                }
            }
        }
        Some("never") => {
            edit.set_if_changed(
                "datum",
                "pooled_mining_only",
                json!(false),
                json!(cfg.datum.pooled_mining_only),
            );
            if !pool_host.is_empty() {
                if let Some(named) = edit.doc.get("datum").and_then(|d| d.get("pool_host")).cloned()
                {
                    edit.set("datum", "pool_host(old)", named);
                }
                edit.set("datum", "pool_host", json!(""));
                pool_host.clear();
            }
        }
        Some(_) => edit.errors.push("Reward sharing must be require, prefer or never".into()),
    }

    if let Some(host) = field("datum_pool_host") {
        let host = host.trim();
        if !pool_host.is_empty() {
            edit.set_if_changed("datum", "pool_host", json!(host), json!(pool_host));
        } else if host != default_host || old_pool_host(edit.doc).is_some() {
            // Not pooled now: the host is parked for when reward sharing is turned on. The
            // default is not written unless something else was parked already.
            let old = old_pool_host(edit.doc).map_or(Value::Null, |o| json!(o));
            edit.set_if_changed("datum", "pool_host(old)", json!(host), old);
        }
    }

    match field("username_behaviour") {
        None => {}
        Some("full_users") => edit.set_if_changed(
            "datum",
            "pool_pass_full_users",
            json!(true),
            json!(cfg.datum.pool_pass_full_users),
        ),
        Some(choice @ ("workers" | "private")) => {
            let workers = choice == "workers";
            edit.set_if_changed(
                "datum",
                "pool_pass_full_users",
                json!(false),
                json!(cfg.datum.pool_pass_full_users),
            );
            edit.set_if_changed(
                "datum",
                "pool_pass_workers",
                json!(workers),
                json!(cfg.datum.pool_pass_workers),
            );
        }
        Some(_) => {
            edit.errors.push("Miner usernames must be full_users, workers or private".into())
        }
    }

    for f in FIELDS {
        let Some(text) = field(f.name) else { continue };
        let current = (f.current)(cfg);
        match f.kind {
            Kind::Text => edit.set_if_changed(f.section, f.key, json!(text.trim()), current),
            Kind::Int(min, max) => match parse_int(f.label, text, min, max) {
                Ok(v) => edit.set_if_changed(f.section, f.key, json!(v), current),
                Err(e) => edit.errors.push(e),
            },
            Kind::Bool => match parse_bool(f.label, text) {
                Ok(v) => edit.set_if_changed(f.section, f.key, json!(v), current),
                Err(e) => edit.errors.push(e),
            },
            Kind::Password => {
                if !text.is_empty() {
                    edit.set(f.section, f.key, json!(text));
                }
            }
        }
    }

    // A longer job interval raises the pool timeout with it, as the C gateway does, instead
    // of refusing the interval for the timeout the file does not name.
    if let Some(seconds) =
        field("bitcoind_work_update_seconds").and_then(|t| t.trim().parse::<u64>().ok())
        && cfg.datum.protocol_global_timeout < seconds + 5
    {
        edit.set("datum", "protocol_global_timeout", json!(seconds + 5));
    }

    let Edit { changed, errors, .. } = edit;
    if !errors.is_empty() {
        return Err(errors);
    }
    if !changed {
        return Ok(None);
    }
    let text = render(&doc);
    Config::parse(&text).map_err(|e| vec![e])?;
    Ok(Some(text))
}

/// Write `text` to `path` through `path.new` and a rename, so a failure leaves the file
/// as it was.
pub fn write_file(path: &str, text: &str) -> std::io::Result<()> {
    let tmp = format!("{path}.new");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)
}

/// Replace the process with a new one on the same command line. The listeners close with
/// the process (every socket and file is close-on-exec), so the new one binds them.
pub fn restart() -> ! {
    log::info!("Restarting to apply the new configuration");
    log::logger().flush();
    // The response to the request that asked for this is on its way out.
    std::thread::sleep(std::time::Duration::from_millis(500));
    let exe = std::env::current_exe()
        .unwrap_or_else(|_| std::env::args_os().next().map(Into::into).unwrap_or_default());
    let mut cmd = std::process::Command::new(exe);
    cmd.args(std::env::args_os().skip(1));
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        let e = cmd.exec();
        log::error!("Could not restart: {e}");
        log::logger().flush();
        std::process::exit(1);
    }
    #[cfg(not(unix))]
    {
        match cmd.spawn() {
            Ok(_) => std::process::exit(0),
            Err(e) => {
                log::error!("Could not restart: {e}");
                log::logger().flush();
                std::process::exit(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal() -> String {
        r#"{
          "bitcoind": {"rpcuser":"u","rpcpassword":"p","rpcurl":"http://127.0.0.1:18443"},
          "mining": {"pool_address":"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"},
          "datum": {"pool_host": "", "pooled_mining_only": false}
        }"#
        .to_string()
    }

    #[test]
    fn parses_the_minimal_file_with_defaults() {
        let c = Config::parse(&minimal()).unwrap();
        assert_eq!(c.stratum.listen_port, 23334);
        assert_eq!(c.stratum.vardiff_min, 16384);
        assert_eq!(c.api.miner_listen_port, 8000);
        assert_eq!(c.bitcoind.work_update_seconds, 40);
        assert!(!c.datum.pooled_mining_only);
        assert_eq!(c.fee_address(), "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080");
    }

    #[test]
    fn the_pool_url_is_empty_unless_set() {
        assert_eq!(Config::parse(&minimal()).unwrap().datum.pool_url, "");
        let text = minimal().replace(
            "\"pooled_mining_only\": false",
            "\"pooled_mining_only\": false, \"pool_url\": \"https://pool.example\"",
        );
        assert_eq!(Config::parse(&text).unwrap().datum.pool_url, "https://pool.example");
    }

    #[test]
    fn a_fee_requires_full_users() {
        let text = minimal().replace(
            "\"pooled_mining_only\": false",
            "\"pooled_mining_only\": false, \"gateway_fee_bps\": 100, \"pool_pass_full_users\": false",
        );
        let e = Config::parse(&text).unwrap_err();
        assert!(e.contains("pool_pass_full_users"), "{e}");
    }

    #[test]
    fn username_modifiers_are_checked() {
        let text = minimal().replace(
            "\"datum\":",
            "\"stratum\": {\"username_modifiers\": {\"half\": {\"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080\": 0.5}}}, \"datum\":",
        );
        let c = Config::parse(&text).unwrap();
        assert_eq!(c.warnings.len(), 1);
        assert!(c.warnings[0].1.contains("not distribute 50% of shares"), "{}", c.warnings[0].1);
        let text = minimal().replace(
            "\"datum\":",
            "\"stratum\": {\"username_modifiers\": {\"bad\": {\"\": -1}}}, \"datum\":",
        );
        assert!(Config::parse(&text).unwrap_err().contains("negative"));
    }

    #[test]
    fn username_modifier_ranges_keep_the_file_order() {
        let text = minimal().replace(
            "\"datum\":",
            "\"stratum\": {\"username_modifiers\": {\"z\": {\"bcrt1qzed\": 0.9, \"bcrt1qamy\": 0.1}, \"a\": {\"\": 1}}}, \"datum\":",
        );
        let c = Config::parse(&text).unwrap();
        let names: Vec<&str> =
            c.stratum.username_modifiers.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["z", "a"]);
        let addrs: Vec<&str> =
            c.stratum.username_modifiers[0].1.iter().map(|(a, _)| a.as_str()).collect();
        assert_eq!(addrs, ["bcrt1qzed", "bcrt1qamy"]);
    }

    #[test]
    fn work_update_seconds_is_clamped() {
        let text = minimal().replace("\"rpcurl\"", "\"work_update_seconds\": 1, \"rpcurl\"");
        let c = Config::parse(&text).unwrap();
        assert_eq!(c.bitcoind.work_update_seconds, 5);
    }

    const FILE: &str = r#"{
    "bitcoind": {"rpcuser": "u", "rpcpassword": "p", "rpcurl": "http://127.0.0.1:18443"},
    "mining": {"pool_address": "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"},
    "datum": {"pool_host": "", "pooled_mining_only": false}
}"#;

    fn form(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn cfg() -> Config {
        Config::parse(FILE).unwrap()
    }

    #[test]
    fn unchanged_values_write_nothing() {
        let c = cfg();
        let f = form(&[
            ("mining_pool_address", "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"),
            ("mining_coinbase_unique_id", "4242"),
            ("bitcoind_rpcpassword", ""),
            ("reward_sharing", "never"),
            ("username_behaviour", "full_users"),
            ("stratum_fingerprint_miners", "1"),
        ]);
        assert_eq!(apply(&c, FILE, &f).unwrap(), None);
    }

    #[test]
    fn edits_are_written_with_the_file_order_kept() {
        let c = cfg();
        let f = form(&[("mining_coinbase_unique_id", "7"), ("stratum_vardiff_min", "1024")]);
        let text = apply(&c, FILE, &f).unwrap().unwrap();
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["mining"]["coinbase_unique_id"], 7);
        assert_eq!(doc["stratum"]["vardiff_min"], 1024);
        let keys: Vec<&str> = doc.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys, ["bitcoind", "mining", "datum", "stratum"]);
        assert!(text.starts_with("{\n    \"bitcoind\""), "{text}");
    }

    #[test]
    fn the_startup_validation_refuses_a_bad_edit() {
        let c = cfg();
        let e = apply(&c, FILE, &form(&[("mining_pool_address", "nonsense")])).unwrap_err();
        assert!(e[0].contains("mining.pool_address"), "{e:?}");
        let e = apply(&c, FILE, &form(&[("mining_coinbase_unique_id", "70000")])).unwrap_err();
        assert_eq!(e, ["Unique gateway ID must be between 0 and 65535"]);
        let e = apply(&c, FILE, &form(&[("datum_pool_port", "x")])).unwrap_err();
        assert_eq!(e, ["Pool port must be a whole number"]);
    }

    #[test]
    fn reward_sharing_parks_and_restores_the_pool_host() {
        let c = cfg();
        // Never mode: a typed host is parked, not applied.
        let text = apply(&c, FILE, &form(&[("datum_pool_host", "pool.example")])).unwrap().unwrap();
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["datum"]["pool_host"], "");
        assert_eq!(doc["datum"]["pool_host(old)"], "pool.example");
        assert_eq!(form_values(&c, &doc)["datum_pool_host"], "pool.example");
        // The default host is not parked.
        let default = Datum::default().pool_host;
        assert_eq!(apply(&c, FILE, &form(&[("datum_pool_host", default.as_str())])).unwrap(), None);

        // Turning sharing on restores the parked host; the port and key come with the form.
        let key = "f21f2f0ef0aa1970468f22bad9bb7f4535146f8e4a8f646bebc93da3d89b1406f40d032f09a417d94dc068055df654937922d2c89522e3e8f6f0e649de473003";
        let f = form(&[
            ("reward_sharing", "require"),
            ("datum_pool_host", "pool.example"),
            ("datum_pool_pubkey", key),
        ]);
        let text = apply(&c, &text, &f).unwrap().unwrap();
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["datum"]["pool_host"], "pool.example");
        assert_eq!(doc["datum"]["pooled_mining_only"], true);
        assert!(doc["datum"].get("pool_host(old)").is_none());

        // And off again parks it.
        let pooled = Config::parse(&text).unwrap();
        let text = apply(&pooled, &text, &form(&[("reward_sharing", "never")])).unwrap().unwrap();
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["datum"]["pool_host"], "");
        assert_eq!(doc["datum"]["pool_host(old)"], "pool.example");
        assert_eq!(doc["datum"]["pooled_mining_only"], false);
    }

    #[test]
    fn username_behaviour_sets_both_flags() {
        let c = cfg();
        let text = apply(&c, FILE, &form(&[("username_behaviour", "workers")])).unwrap().unwrap();
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["datum"]["pool_pass_full_users"], false);
        assert!(doc["datum"].get("pool_pass_workers").is_none(), "the default is kept");
        let text = apply(&c, FILE, &form(&[("username_behaviour", "private")])).unwrap().unwrap();
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["datum"]["pool_pass_full_users"], false);
        assert_eq!(doc["datum"]["pool_pass_workers"], false);
    }

    #[test]
    fn a_longer_job_interval_raises_the_pool_timeout() {
        let c = cfg();
        let text =
            apply(&c, FILE, &form(&[("bitcoind_work_update_seconds", "100")])).unwrap().unwrap();
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["bitcoind"]["work_update_seconds"], 100);
        assert_eq!(doc["datum"]["protocol_global_timeout"], 105);
    }

    #[test]
    fn the_password_is_never_shown_and_kept_when_blank() {
        let c = cfg();
        let shown = form_values(&c, &Value::Null);
        assert!(shown.get("bitcoind_rpcpassword").is_none());
        assert_eq!(shown["bitcoind_rpcuser"], "u");
        assert_eq!(shown["reward_sharing"], "never");
        let f = form(&[("bitcoind_rpcpassword", "new"), ("bitcoind_rpcuser", "u")]);
        let text = apply(&c, FILE, &f).unwrap().unwrap();
        let doc: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(doc["bitcoind"]["rpcpassword"], "new");
    }
}
