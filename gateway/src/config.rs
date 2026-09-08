use serde::Deserialize;
use serde_json::{Value, json};

const EXTRA_JOBS_PER_TIP: u64 = 2;

const MAX_THREADS: usize = 64;
const MAX_CLIENTS_THREAD: usize = 4096;
const WORK_UPDATE_SECONDS_RANGE: std::ops::RangeInclusive<u64> = 5..=120;
const MIN_VARDIFF_TARGET_SHARES_MIN: u64 = 1;
const MIN_VARDIFF_QUICKDIFF_COUNT: u64 = 4;
const MIN_VARDIFF_QUICKDIFF_DELTA: u64 = 3;
const SHARE_STALE_SECONDS_RANGE: std::ops::RangeInclusive<u64> = 60..=150;
const GLOBAL_TIMEOUT_MARGIN_SECS: u64 = 5;
const MAX_PORT: i64 = u16::MAX as i64;
const MAX_COINBASE_UNIQUE_ID: i64 = u16::MAX as i64;

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
    #[serde(deserialize_with = "deserialize_modifiers")]
    pub username_modifiers: crate::username::Modifiers,
}

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
    pub pool_url: String,
    pub pool_pubkey: String,
    pub pool_pass_workers: bool,
    pub protocol_job_slots: usize,
    pub pool_pass_full_users: bool,
    pub gateway_fee_bps: u32,
    pub gateway_fee_address: String,
    pub always_pay_self: Option<bool>,
    pub pooled_mining_only: bool,
    pub protocol_global_timeout: u64,
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
    #[serde(skip)]
    pub warnings: Vec<(log::Level, String)>,
    #[serde(skip)]
    pub pool_output_script: Vec<u8>,
}

pub const MAX_COINBASE_TAG_SPACE: usize = 86;
pub const WIDE_PRIME_PUSH_EXTRA_BYTES: usize = 4;

pub const MAX_CONFIGURED_TAG: usize = 60;
pub const MAX_CONFIGURED_TAGS_TOTAL: usize = 88;

impl Config {
    pub fn parse(text: &str) -> Result<Config, String> {
        let mut c: Config = serde_json::from_str(text).map_err(|e| e.to_string())?;
        c.validate()?;
        Ok(c)
    }

    fn validate(&mut self) -> Result<(), String> {
        self.validate_bitcoind()?;
        self.validate_stratum()?;
        self.validate_mining()?;
        self.validate_api();
        self.validate_logger();
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
        self.bitcoind.work_update_seconds = self
            .bitcoind
            .work_update_seconds
            .clamp(*WORK_UPDATE_SECONDS_RANGE.start(), *WORK_UPDATE_SECONDS_RANGE.end());
        Ok(())
    }

    fn validate_stratum(&mut self) -> Result<(), String> {
        let s = &self.stratum;
        if s.max_threads > MAX_THREADS {
            return Err(format!("stratum.max_threads must be at most {MAX_THREADS}"));
        }
        if s.max_clients_per_thread > MAX_CLIENTS_THREAD {
            return Err(format!(
                "stratum.max_clients_per_thread must be at most {MAX_CLIENTS_THREAD}"
            ));
        }
        if s.max_clients > s.max_clients_per_thread * s.max_threads {
            return Err("stratum.max_clients exceeds max_clients_per_thread * max_threads".into());
        }
        if s.vardiff_min == 0 {
            return Err("stratum.vardiff_min must be at least 1".into());
        }
        if s.vardiff_target_shares_min < MIN_VARDIFF_TARGET_SHARES_MIN {
            return Err(format!(
                "stratum.vardiff_target_shares_min must be at least {MIN_VARDIFF_TARGET_SHARES_MIN}"
            ));
        }
        if s.vardiff_quickdiff_count < MIN_VARDIFF_QUICKDIFF_COUNT {
            return Err(format!(
                "stratum.vardiff_quickdiff_count must be at least {MIN_VARDIFF_QUICKDIFF_COUNT}"
            ));
        }
        if s.vardiff_quickdiff_delta < MIN_VARDIFF_QUICKDIFF_DELTA {
            return Err(format!(
                "stratum.vardiff_quickdiff_delta must be at least {MIN_VARDIFF_QUICKDIFF_DELTA}"
            ));
        }
        if !SHARE_STALE_SECONDS_RANGE.contains(&s.share_stale_seconds) {
            return Err(format!(
                "stratum.share_stale_seconds must be {}..{}",
                SHARE_STALE_SECONDS_RANGE.start(),
                SHARE_STALE_SECONDS_RANGE.end()
            ));
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
        if tags > MAX_CONFIGURED_TAGS_TOTAL
            || m.coinbase_tag_primary.len() > MAX_CONFIGURED_TAG
            || m.coinbase_tag_secondary.len() > MAX_CONFIGURED_TAG
        {
            return Err(format!(
                "mining.coinbase_tag_primary and mining.coinbase_tag_secondary must be at most \
                 {MAX_CONFIGURED_TAG} bytes each and {MAX_CONFIGURED_TAGS_TOTAL} bytes together"
            ));
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
    }

    fn validate_logger(&mut self) {
        if self.logger.log_rotate_daily.is_some() {
            self.warn("logger.log_rotate_daily has no effect: the file is held open, so rotate it with logrotate's copytruncate");
        }
    }

    fn validate_datum(&mut self) -> Result<(), String> {
        let d = &self.datum;
        if !(1..=ratum::datum::share::MAX_JOBS).contains(&d.protocol_job_slots) {
            return Err(format!(
                "datum.protocol_job_slots must be 1..{}",
                ratum::datum::share::MAX_JOBS
            ));
        }
        let min_slots = EXTRA_JOBS_PER_TIP
            + (self.stratum.share_stale_seconds + self.bitcoind.work_update_seconds)
                .div_ceil(self.bitcoind.work_update_seconds);
        if (d.protocol_job_slots as u64) < min_slots {
            return Err(format!(
                "datum.protocol_job_slots must be at least {min_slots} for stratum.share_stale_seconds {} and bitcoind.work_update_seconds {}",
                self.stratum.share_stale_seconds, self.bitcoind.work_update_seconds
            ));
        }
        if d.protocol_global_timeout
            < self.bitcoind.work_update_seconds + GLOBAL_TIMEOUT_MARGIN_SECS
        {
            return Err(format!(
                "datum.protocol_global_timeout must be at least bitcoind.work_update_seconds + \
                 {GLOBAL_TIMEOUT_MARGIN_SECS}"
            ));
        }
        if d.pooled_mining_only && d.pool_host.is_empty() {
            return Err("datum.pooled_mining_only requires datum.pool_host".into());
        }
        if u64::from(d.gateway_fee_bps) > ratum::BASIS_POINTS_PER_UNIT {
            return Err(format!(
                "datum.gateway_fee_bps must be 0..{}",
                ratum::BASIS_POINTS_PER_UNIT
            ));
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
                if (sum * crate::username::SELECTOR_SPACE).ceil() - 1.0
                    >= crate::username::SELECTOR_MAX as f64
                {
                    covered = true;
                    break;
                }
            }
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

    pub fn stale_window(&self) -> std::time::Duration {
        std::time::Duration::from_secs(
            self.stratum.share_stale_seconds + self.bitcoind.work_update_seconds,
        )
    }

    pub fn share_queue_capacity(&self) -> usize {
        let s = &self.stratum;
        s.max_clients_per_thread
            * s.vardiff_target_shares_min as usize
            * (s.share_stale_seconds / ratum::SECS_PER_MINUTE) as usize
            * 16
    }

    pub fn dupe_table_capacity(&self) -> usize {
        self.share_queue_capacity() * self.stratum.max_threads
    }

    pub fn fee_address(&self) -> &str {
        if self.datum.gateway_fee_address.is_empty() {
            &self.mining.pool_address
        } else {
            &self.datum.gateway_fee_address
        }
    }
}

struct Field {
    name: &'static str,
    label: &'static str,
    section: &'static str,
    key: &'static str,
    kind: Kind,
    current: fn(&Config) -> Value,
}

enum Kind {
    Text,
    Int(i64, i64),
    Bool,
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
        kind: Kind::Int(0, MAX_COINBASE_UNIQUE_ID),
        current: |c| json!(c.mining.coinbase_unique_id),
    },
    Field {
        name: "datum_pool_port",
        label: "Pool port",
        section: "datum",
        key: "pool_port",
        kind: Kind::Int(1, MAX_PORT),
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
        kind: Kind::Int(0, ratum::BASIS_POINTS_PER_UNIT as i64),
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
        kind: Kind::Int(1, MAX_PORT),
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
        kind: Kind::Int(
            *WORK_UPDATE_SECONDS_RANGE.start() as i64,
            *WORK_UPDATE_SECONDS_RANGE.end() as i64,
        ),
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

fn shown_pool_host(cfg: &Config, doc: &Value) -> String {
    if !cfg.datum.pool_host.is_empty() {
        return cfg.datum.pool_host.clone();
    }
    old_pool_host(doc).unwrap_or_else(|| Datum::default().pool_host)
}

fn old_pool_host(doc: &Value) -> Option<String> {
    doc.get("datum")?.get("pool_host(old)")?.as_str().map(str::to_string)
}

fn secondary_tag_max(cfg: &Config) -> usize {
    MAX_CONFIGURED_TAGS_TOTAL
        .saturating_sub(cfg.mining.coinbase_tag_primary.len())
        .min(MAX_CONFIGURED_TAG)
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

fn section<'a>(
    doc: &'a mut Value,
    name: &str,
) -> Result<&'a mut serde_json::Map<String, Value>, String> {
    let root = doc.as_object_mut().ok_or("the configuration file is not a JSON object")?;
    let entry = root.entry(name).or_insert_with(|| Value::Object(Default::default()));
    entry.as_object_mut().ok_or_else(|| format!("the file's \"{name}\" is not a JSON object"))
}

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

fn render(doc: &Value) -> String {
    let mut out = Vec::new();
    let fmt = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    let mut ser = serde_json::Serializer::with_formatter(&mut out, fmt);
    serde::Serialize::serialize(doc, &mut ser).expect("a Value serializes");
    out.push(b'\n');
    String::from_utf8(out).expect("JSON is UTF-8")
}

fn submitted<'a>(form: &'a [(String, String)], name: &str) -> Option<&'a str> {
    form.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

fn apply_reward_sharing(edit: &mut Edit<'_>, cfg: &Config, form: &[(String, String)]) {
    let mut pool_host = cfg.datum.pool_host.clone();
    let default_host = Datum::default().pool_host;
    match submitted(form, "reward_sharing") {
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

    if let Some(host) = submitted(form, "datum_pool_host") {
        let host = host.trim();
        if !pool_host.is_empty() {
            edit.set_if_changed("datum", "pool_host", json!(host), json!(pool_host));
        } else if host != default_host || old_pool_host(edit.doc).is_some() {
            let old = old_pool_host(edit.doc).map_or(Value::Null, |o| json!(o));
            edit.set_if_changed("datum", "pool_host(old)", json!(host), old);
        }
    }
}

fn apply_username_behaviour(edit: &mut Edit<'_>, cfg: &Config, form: &[(String, String)]) {
    match submitted(form, "username_behaviour") {
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
}

pub fn apply(
    cfg: &Config,
    file_text: &str,
    form: &[(String, String)],
) -> Result<Option<String>, Vec<String>> {
    let mut doc: Value = serde_json::from_str(file_text)
        .map_err(|e| vec![format!("the configuration file is not valid JSON: {e}")])?;
    let mut edit = Edit { doc: &mut doc, changed: false, errors: Vec::new() };

    apply_reward_sharing(&mut edit, cfg, form);
    apply_username_behaviour(&mut edit, cfg, form);

    for f in FIELDS {
        let Some(text) = submitted(form, f.name) else { continue };
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

    if let Some(seconds) =
        submitted(form, "bitcoind_work_update_seconds").and_then(|t| t.trim().parse::<u64>().ok())
        && cfg.datum.protocol_global_timeout < seconds + GLOBAL_TIMEOUT_MARGIN_SECS
    {
        edit.set("datum", "protocol_global_timeout", json!(seconds + GLOBAL_TIMEOUT_MARGIN_SECS));
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

pub fn write_file(path: &str, text: &str) -> std::io::Result<()> {
    let tmp = format!("{path}.new");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)
}

pub fn restart() -> ! {
    log::info!("Restarting to apply the new configuration");
    log::logger().flush();
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
