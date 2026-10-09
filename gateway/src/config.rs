//! The configuration file: the C gateway's JSON schema with its defaults, the checks applied to it
//! at startup, and the values derived from it that more than one thread reads.

use crate::username::{ModifierRange, UsernameModifier};
use ratum::bitcoin::address;
use ratum::datum::coinbase;
use ratum::datum::messages::config::ClientConfig;
use serde::Deserialize;
use std::time::Duration;

/// The job slots a new tip takes beyond the one a periodic template update takes: the
/// priority job, which serves the tip before its split is known, and the job `on_coinbaser`
/// builds once the pool has answered the coinbaser request. The priority job is published
/// twice, once under each of its two coinbases, but both publications are the one job in
/// the one slot.
const EXTRA_JOBS_PER_TIP: u64 = 1;

const MAX_THREADS: usize = 64;
const MAX_CLIENTS_PER_THREAD: usize = 4096;
/// The bounds the settings page and the startup checks share, so a field's limits are
/// declared once. Every one is in u64 whatever the field's own width, which is what lets
/// `in_range` and the form's `int` read them all.
pub const WORK_UPDATE_SECONDS_RANGE: std::ops::RangeInclusive<u64> = 5..=120;
pub const PORT_RANGE: std::ops::RangeInclusive<u64> = 1..=u16::MAX as u64;
pub const VARDIFF_MIN_RANGE: std::ops::RangeInclusive<u64> = 1..=crate::difficulty::MAX;
pub const COINBASE_UNIQUE_ID_RANGE: std::ops::RangeInclusive<u64> = 0..=u16::MAX as u64;
const MIN_VARDIFF_TARGET_SHARES_MIN: u64 = 1;
const MIN_VARDIFF_QUICKDIFF_COUNT: u64 = 4;
const MIN_VARDIFF_QUICKDIFF_DELTA: u64 = 3;
/// The most shares a minute `stratum.vardiff_target_shares_min` may ask for. Vardiff's target
/// is `60000 / vardiff_target_shares_min` milliseconds per share, and it compares a measured
/// rate against that target divided by 2 (to double) and by `vardiff_quickdiff_delta` (to
/// raise at once). At this bound the target is 3 ms, so both quotients are still nonzero at
/// the smallest delta of 3; above 60000 the target itself is 0. `shares_in_stale_window`
/// multiplies it by at most 262144 clients, 2 minutes and a headroom of 16, about 1.7e11,
/// which a 64-bit usize holds.
const MAX_VARDIFF_TARGET_SHARES_MIN: u64 =
    ratum::SECS_PER_MINUTE * 1000 / MIN_VARDIFF_QUICKDIFF_DELTA;
const SHARE_STALE_SECONDS_RANGE: std::ops::RangeInclusive<u64> = 60..=150;
pub const GLOBAL_TIMEOUT_MARGIN_SECS: u64 = 5;
/// The longest `datum.protocol_global_timeout`. The DATUM session adds the timeout to
/// `Instant::now()`, which panics on overflow for values near u64::MAX seconds; a day is far
/// above any interval the pool is expected to stay silent for.
const MAX_PROTOCOL_GLOBAL_TIMEOUT_SECS: u64 = ratum::SECS_PER_DAY;
const JOB_RETENTION_STALE_WINDOWS: u32 = 2;
/// How many times the shares the stale window holds the share queue and the duplicate-share
/// table are sized to, so a burst above the vardiff target does not fill either.
const SHARE_CAPACITY_HEADROOM: usize = 16;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct BitcoindConfig {
    pub rpccookiefile: String,
    pub rpcuser: String,
    pub rpcpassword: String,
    pub rpcurl: String,
    pub work_update_seconds: u64,
    pub notify_fallback: bool,
}

impl Default for BitcoindConfig {
    fn default() -> Self {
        Self {
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
pub struct StratumConfig {
    pub listen_addr: String,
    pub listen_port: u16,
    pub max_clients_per_thread: usize,
    pub max_threads: usize,
    pub max_clients: usize,
    pub trust_proxy: i64,
    /// `stratum.vardiff_min` as written; `validate_stratum` parses it into `vardiff_min`.
    #[serde(rename = "vardiff_min")]
    vardiff_min_input: serde_json::Value,
    #[serde(skip)]
    pub vardiff_min: u64,
    pub vardiff_target_shares_min: u64,
    pub vardiff_quickdiff_count: u64,
    pub vardiff_quickdiff_delta: u64,
    pub share_stale_seconds: u64,
    pub idle_timeout_no_subscribe: u64,
    pub idle_timeout_no_shares: u64,
    pub idle_timeout_max_last_work: u64,
    pub require_address_username: bool,
    #[serde(deserialize_with = "deserialize_modifiers")]
    pub username_modifiers: Vec<UsernameModifier>,
}

/// `username_modifiers` as the C gateway reads it: an object of modifier name to an object
/// of address to proportion, both in file order (serde_json keeps it: `preserve_order`).
fn deserialize_modifiers<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Vec<UsernameModifier>, D::Error> {
    use serde::de::Error as _;
    use serde_json::{Map, Value};

    let modifiers = Map::<String, Value>::deserialize(d)?;
    modifiers
        .into_iter()
        .map(|(name, ranges)| {
            let Value::Object(ranges) = ranges else {
                return Err(D::Error::custom(format!(
                    "stratum.username_modifiers.{name} must be an object of address to proportion"
                )));
            };
            let ranges = ranges
                .into_iter()
                .map(|(address, proportion)| match proportion.as_f64() {
                    Some(proportion) => Ok(ModifierRange { address, proportion }),
                    None => Err(D::Error::custom(format!(
                        "stratum.username_modifiers.{name}.{address} must be a number"
                    ))),
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(UsernameModifier { name, ranges })
        })
        .collect()
}

impl StratumConfig {
    /// Whether `require_address_username` refuses this username: the rule the authorize
    /// reply, the share check and the admin page's unpayable mark all apply.
    pub fn refuses_username(&self, username: &str) -> bool {
        self.require_address_username
            && !crate::username::is_payable(username, &self.username_modifiers)
    }
}

impl Default for StratumConfig {
    fn default() -> Self {
        Self {
            listen_addr: String::new(),
            listen_port: 23334,
            max_clients_per_thread: 128,
            max_threads: 8,
            max_clients: 1024,
            trust_proxy: -1,
            vardiff_min_input: serde_json::Value::Null,
            vardiff_min: 16384,
            vardiff_target_shares_min: 8,
            vardiff_quickdiff_count: 8,
            vardiff_quickdiff_delta: 8,
            share_stale_seconds: 120,
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
pub struct MiningConfig {
    pub pool_address: String,
    pub coinbase_tag_primary: String,
    pub coinbase_tag_secondary: String,
    pub coinbase_unique_id: u32,
    pub save_submitblocks_dir: String,
    /// C keys with no effect here, read so a set value is reported at startup.
    pub allow_hasher_time_rolling: Option<bool>,
    pub abw_verify_all_shares_on_disclosure: Option<bool>,
}

impl Default for MiningConfig {
    fn default() -> Self {
        Self {
            pool_address: String::new(),
            coinbase_tag_primary: String::new(),
            coinbase_tag_secondary: String::new(),
            coinbase_unique_id: 4242,
            save_submitblocks_dir: String::new(),
            allow_hasher_time_rolling: None,
            abw_verify_all_shares_on_disclosure: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ApiConfig {
    pub admin_password: String,
    pub allow_insecure_auth: bool,
    pub listen_addr: String,
    pub listen_port: u16,
    pub miner_listen_addr: String,
    pub miner_listen_port: u16,
    pub modify_conf: bool,
}

impl Default for ApiConfig {
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
pub struct ExtraBlockSubmissionsConfig {
    pub urls: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LoggerConfig {
    pub log_to_console: bool,
    pub log_to_stderr: bool,
    pub log_to_file: bool,
    pub log_file: String,
    pub log_rotate_daily: bool,
    pub log_calling_function: bool,
    pub log_level_console: u8,
    pub log_level_file: u8,
}

impl Default for LoggerConfig {
    fn default() -> Self {
        Self {
            log_to_console: true,
            log_to_stderr: false,
            log_to_file: false,
            log_file: String::new(),
            log_rotate_daily: true,
            log_calling_function: true,
            log_level_console: 2,
            log_level_file: 1,
        }
    }
}

/// A DATUM pool: the `datum` section's own `pool_*` keys, and each entry of
/// `datum.fallback_pools`. The defaults are the Ocean pool.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Pool {
    pub pool_host: String,
    pub pool_port: u16,
    pub pool_pubkey: String,
    pub pool_url: String,
}

impl Default for Pool {
    fn default() -> Self {
        Self {
            pool_host: "datum-beta1.mine.ocean.xyz".into(),
            pool_port: 28915,
            pool_pubkey: "f21f2f0ef0aa1970468f22bad9bb7f4535146f8e4a8f646bebc93da3d89b1406f40d032f09a417d94dc068055df654937922d2c89522e3e8f6f0e649de473003".into(),
            pool_url: String::new(),
        }
    }
}

impl Pool {
    pub fn address(&self) -> String {
        format!("{}:{}", self.pool_host, self.pool_port)
    }

    /// `pool_pubkey` parsed; the error reads as the predicate of a sentence naming the key.
    pub fn pubkey(&self) -> Result<ratum::datum::keys::PublicKeys, String> {
        ratum::datum::keys::PublicKeys::from_hex(&self.pool_pubkey)
    }

    /// The checks a pool the gateway connects to must pass, each error naming the key under
    /// `name` (`datum`, or `datum.fallback_pools[i]`).
    fn check(&self, name: &str) -> Result<(), String> {
        if self.pool_host.is_empty() {
            return Err(format!("{name}.pool_host is empty"));
        }
        in_range(&format!("{name}.pool_port"), u64::from(self.pool_port), &PORT_RANGE)?;
        self.pubkey().map_err(|e| format!("{name}.pool_pubkey {e}"))?;
        self.check_url(name)
    }

    /// The status page links the pool's name to `pool_url`, so a scheme a browser runs
    /// (javascript:, data:) is refused.
    fn check_url(&self, name: &str) -> Result<(), String> {
        if !self.pool_url.is_empty() && !is_web_url(&self.pool_url) {
            return Err(format!("{name}.pool_url must begin with http:// or https://"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DatumConfig {
    /// `pool_host`, `pool_port`, `pool_pubkey` and `pool_url`, the keys of this section.
    #[serde(flatten)]
    pub pool: Pool,
    /// Pools tried in order when the one before them is unreachable; not a C key.
    pub fallback_pools: Vec<Pool>,
    pub pool_pass_workers: bool,
    pub protocol_job_slots: usize,
    pub pool_pass_full_users: bool,
    pub always_pay_self: Option<bool>,
    pub pooled_mining_only: bool,
    pub protocol_global_timeout: u64,
    pub protocol_v3: bool,
    /// A C key with no effect here, read so a set value is reported at startup.
    pub migration_max_seconds: Option<i64>,
}

impl Default for DatumConfig {
    fn default() -> Self {
        Self {
            pool: Pool::default(),
            fallback_pools: Vec::new(),
            pool_pass_workers: true,
            protocol_job_slots: 256,
            pool_pass_full_users: true,
            always_pay_self: None,
            pooled_mining_only: true,
            protocol_global_timeout: 60,
            protocol_v3: true,
            migration_max_seconds: None,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub bitcoind: BitcoindConfig,
    pub stratum: StratumConfig,
    pub mining: MiningConfig,
    pub api: ApiConfig,
    pub extra_block_submissions: ExtraBlockSubmissionsConfig,
    pub logger: LoggerConfig,
    pub datum: DatumConfig,
    #[serde(skip)]
    pub startup_notes: Vec<StartupNote>,
    #[serde(skip)]
    pub pool_output_script: Vec<u8>,
    /// The `datum` section's pool first, then `datum.fallback_pools`, each checked; empty
    /// while `datum.pool_host` is empty (non-pooled mining).
    #[serde(skip)]
    pub pools: Vec<Pool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupNote {
    pub level: log::Level,
    pub message: String,
}

pub const MAX_CONFIGURED_TAG_LEN: usize = 60;
pub const MAX_CONFIGURED_TAGS_TOTAL_LEN: usize = 88;

fn at_least(name: &str, value: u64, min: u64) -> Result<(), String> {
    if value < min { Err(format!("{name} must be at least {min}")) } else { Ok(()) }
}

fn at_most(name: &str, value: u64, max: u64) -> Result<(), String> {
    if value > max { Err(format!("{name} must be at most {max}")) } else { Ok(()) }
}

fn in_range(name: &str, value: u64, range: &std::ops::RangeInclusive<u64>) -> Result<(), String> {
    if range.contains(&value) {
        return Ok(());
    }
    Err(format!("{name} must be {}..{}", range.start(), range.end()))
}

/// Whether `url` begins with http:// or https://, in any letter case.
pub fn is_web_url(url: &str) -> bool {
    ["http://", "https://"]
        .iter()
        .any(|scheme| url.get(..scheme.len()).is_some_and(|s| s.eq_ignore_ascii_case(scheme)))
}

impl Config {
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut c: Self = serde_json::from_str(text).map_err(|e| e.to_string())?;
        c.validate()?;
        Ok(c)
    }

    fn validate(&mut self) -> Result<(), String> {
        self.validate_bitcoind()?;
        self.validate_stratum()?;
        self.validate_mining()?;
        self.validate_api();
        self.validate_datum()?;
        self.validate_username_modifiers()
    }

    fn note_warning(&mut self, message: impl Into<String>) {
        self.startup_notes.push(StartupNote { level: log::Level::Warn, message: message.into() });
    }

    fn validate_bitcoind(&mut self) -> Result<(), String> {
        if self.bitcoind.rpcurl.is_empty() {
            return Err("Required configuration option (bitcoind.rpcurl) not found".into());
        }
        // The check the node client applies at startup, so a file the settings page saves
        // with a URL the client refuses is refused before it is written.
        ratum::rpc::check_url(&self.bitcoind.rpcurl).map_err(|e| {
            format!("bitcoind.rpcurl must be an http:// or https:// URL naming a host: {e}")
        })?;
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
        at_most("stratum.max_threads", s.max_threads as u64, MAX_THREADS as u64)?;
        at_most(
            "stratum.max_clients_per_thread",
            s.max_clients_per_thread as u64,
            MAX_CLIENTS_PER_THREAD as u64,
        )?;
        if s.max_clients > s.max_clients_per_thread * s.max_threads {
            return Err("stratum.max_clients exceeds max_clients_per_thread * max_threads".into());
        }
        in_range("stratum.listen_port", u64::from(s.listen_port), &PORT_RANGE)?;
        self.parse_vardiff_min()?;
        let s = &self.stratum;
        in_range("stratum.vardiff_min", s.vardiff_min, &VARDIFF_MIN_RANGE)?;
        at_least(
            "stratum.vardiff_target_shares_min",
            s.vardiff_target_shares_min,
            MIN_VARDIFF_TARGET_SHARES_MIN,
        )?;
        at_most(
            "stratum.vardiff_target_shares_min",
            s.vardiff_target_shares_min,
            MAX_VARDIFF_TARGET_SHARES_MIN,
        )?;
        at_least(
            "stratum.vardiff_quickdiff_count",
            s.vardiff_quickdiff_count,
            MIN_VARDIFF_QUICKDIFF_COUNT,
        )?;
        at_least(
            "stratum.vardiff_quickdiff_delta",
            s.vardiff_quickdiff_delta,
            MIN_VARDIFF_QUICKDIFF_DELTA,
        )?;
        in_range("stratum.share_stale_seconds", s.share_stale_seconds, &SHARE_STALE_SECONDS_RANGE)?;
        if !s.vardiff_min.is_power_of_two() {
            let rounded = ratum::target::pow2_floor(s.vardiff_min);
            let was = s.vardiff_min;
            self.stratum.vardiff_min = rounded;
            self.note_warning(format!(
                "stratum.vardiff_min {was} is not a power of two; using {rounded}"
            ));
        }
        if self.stratum.trust_proxy != -1 {
            self.note_warning("stratum.trust_proxy is set but the PROXY protocol is not supported; a connection that sends a PROXY line is closed");
        }
        Ok(())
    }

    fn parse_vardiff_min(&mut self) -> Result<(), String> {
        use crate::difficulty::{Parsed, format, parse};
        if self.stratum.vardiff_min_input.is_null() {
            return Ok(());
        }
        let parsed = parse(&self.stratum.vardiff_min_input).ok_or_else(|| {
            format!(
                "stratum.vardiff_min must be a positive integer or a decimal hash count with an optional SI suffix (\"4.4T\"), at most \"{}\"",
                format(crate::difficulty::MAX)
            )
        })?;
        match parsed {
            Parsed::Exact(d) => self.stratum.vardiff_min = d,
            Parsed::RoundedUp(d) => {
                self.stratum.vardiff_min = d;
                self.note_warning(format!("stratum.vardiff_min rounded up to {}", format(d)));
            }
            Parsed::Legacy(d) => {
                self.stratum.vardiff_min = d;
                self.note_warning(format!(
                    "stratum.vardiff_min uses legacy integer syntax; use \"{}\" instead",
                    format(ratum::target::pow2_floor(d))
                ));
            }
        }
        Ok(())
    }

    fn validate_mining(&mut self) -> Result<(), String> {
        let m = &self.mining;
        if m.pool_address.is_empty() {
            return Err("Required configuration option (mining.pool_address) not found".into());
        }
        in_range(
            "mining.coinbase_unique_id",
            u64::from(m.coinbase_unique_id),
            &COINBASE_UNIQUE_ID_RANGE,
        )?;
        let tags = m.coinbase_tag_primary.len() + m.coinbase_tag_secondary.len();
        if tags > MAX_CONFIGURED_TAGS_TOTAL_LEN
            || m.coinbase_tag_primary.len() > MAX_CONFIGURED_TAG_LEN
            || m.coinbase_tag_secondary.len() > MAX_CONFIGURED_TAG_LEN
        {
            return Err(format!(
                "mining.coinbase_tag_primary and mining.coinbase_tag_secondary must be at most \
                 {MAX_CONFIGURED_TAG_LEN} bytes each and {MAX_CONFIGURED_TAGS_TOTAL_LEN} bytes together"
            ));
        }
        self.pool_output_script = address::to_output_script(&m.pool_address, None)
            .ok_or("mining.pool_address is not an address a coinbase output can pay")?;
        // The configured limits above are the C gateway's and are wider than the scriptSig
        // budget, so say which tags `script_sig` will shorten rather than shortening silently.
        let fits = coinbase::max_tag_bytes(false);
        if tags > fits {
            self.note_warning(format!(
                "mining.coinbase_tag_primary and mining.coinbase_tag_secondary total {tags} \
                 bytes, but only {fits} fit a coinbase scriptSig ({} under a version 3 pool), \
                 so the secondary tag is shortened in the work built from them",
                coinbase::max_tag_bytes(true)
            ));
        }
        Ok(())
    }

    fn validate_api(&mut self) {
        if self.api.allow_insecure_auth {
            self.note_warning(
                "api.allow_insecure_auth has no effect: the API uses HTTP Basic authentication",
            );
        }
        if self.api.modify_conf && self.api.admin_password.is_empty() {
            self.note_warning("api.modify_conf is set but api.admin_password is empty, so the settings page cannot save");
        }
    }

    fn validate_datum(&mut self) -> Result<(), String> {
        let d = &self.datum;
        if !(1..=ratum::datum::messages::share::MAX_JOBS).contains(&d.protocol_job_slots) {
            return Err(format!(
                "datum.protocol_job_slots must be 1..{}",
                ratum::datum::messages::share::MAX_JOBS
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
        at_most(
            "datum.protocol_global_timeout",
            d.protocol_global_timeout,
            MAX_PROTOCOL_GLOBAL_TIMEOUT_SECS,
        )?;
        // Checked in non-pooled mode as well: the settings page shows the URL.
        d.pool.check_url("datum")?;
        if d.pooled_mining_only && d.pool.pool_host.is_empty() {
            return Err("datum.pooled_mining_only requires datum.pool_host".into());
        }
        if !d.pool.pool_host.is_empty() {
            d.pool.check("datum")?;
            let mut pools = vec![d.pool.clone()];
            for (i, f) in d.fallback_pools.iter().enumerate() {
                let name = format!("datum.fallback_pools[{i}]");
                f.check(&name)?;
                if pools.iter().any(|p| p.address() == f.address()) {
                    return Err(format!("{name} names {} again", f.address()));
                }
                pools.push(f.clone());
            }
            self.pools = pools;
        } else if !d.fallback_pools.is_empty() {
            self.note_warning(
                "datum.fallback_pools is ignored: datum.pool_host is empty (non-pooled mining)",
            );
        }
        if self.stratum.require_address_username && !self.datum.pool_pass_full_users {
            self.note_warning("stratum.require_address_username is set but datum.pool_pass_full_users is not, so the pool never receives the address the username was checked for");
        }
        if self.datum.always_pay_self.is_some() {
            self.note_warning("datum.always_pay_self has no effect: the coinbase always pays the pool script the split leaves");
        }
        if self.mining.allow_hasher_time_rolling == Some(true) {
            self.note_warning("mining.allow_hasher_time_rolling has no effect: jobs never set the time-offset flag, so hashers do not roll the block time");
        }
        if self.mining.abw_verify_all_shares_on_disclosure == Some(true) {
            self.note_warning("mining.abw_verify_all_shares_on_disclosure has no effect: this gateway retains no anti-block-withholding proofs and does not audit the pool's reveals (the pool relays every block)");
        }
        if self.datum.migration_max_seconds.is_some_and(|secs| secs != 0) {
            self.note_warning("datum.migration_max_seconds has no effect: a migration request from the pool is logged and not followed");
        }
        Ok(())
    }

    fn validate_username_modifiers(&mut self) -> Result<(), String> {
        let mut notes = Vec::new();
        for modifier in &self.stratum.username_modifiers {
            let modname = &modifier.name;
            if let Some(range) = modifier
                .ranges
                .iter()
                .find(|r| !r.address.is_empty() && !address::is_valid(&r.address, None))
            {
                return Err(format!(
                    "stratum.username_modifiers.{modname}.{} is not an address a coinbase output \
                     can pay; the pool refuses every share credited to it",
                    range.address
                ));
            }
            if let Some(range) = modifier.ranges.iter().find(|r| r.proportion < 0.0) {
                return Err(format!(
                    "stratum.username_modifiers.{modname}.{} is negative",
                    range.address
                ));
            }
            if let Some(uncovered) = crate::username::uncovered_share(modifier) {
                notes.push(StartupNote {
                    level: log::Level::Error,
                    message: format!(
                        "Username modifier '{modname}' is configured to not distribute {}% of shares!",
                        100.0 * uncovered
                    ),
                });
            }
        }
        self.startup_notes.extend(notes);
        Ok(())
    }

    pub fn stale_window(&self) -> Duration {
        Duration::from_secs(self.stratum.share_stale_seconds + self.bitcoind.work_update_seconds)
    }

    /// How long a job stays in the job table. Past the stale window a share on the job is
    /// refused (`stale-work`), so the margin covers the one use left: a block found on such
    /// work, whose share resolves the slot before it is sent to the pool.
    pub fn job_retention(&self) -> Duration {
        self.stale_window() * JOB_RETENTION_STALE_WINDOWS
    }

    pub fn protocol_global_timeout(&self) -> Duration {
        Duration::from_secs(self.datum.protocol_global_timeout)
    }

    /// The most shares every client together can produce inside the stale window, with
    /// headroom. Vardiff assigns each client a difficulty targeting
    /// `stratum.vardiff_target_shares_min` shares a minute, so this is that rate over the
    /// window across `stratum.max_clients`. It bounds both structures the whole gateway keeps
    /// one of: the queue of shares waiting for the pool and the duplicate-share table.
    ///
    /// `stratum.max_clients_per_thread` and `stratum.max_threads` do not appear: the gateway
    /// serves one thread per connection, so neither bounds anything it does. They are read
    /// only for the C gateway's `max_clients <= max_clients_per_thread * max_threads` check.
    pub fn shares_in_stale_window(&self) -> usize {
        let s = &self.stratum;
        s.max_clients
            .saturating_mul(s.vardiff_target_shares_min as usize)
            .saturating_mul((s.share_stale_seconds / ratum::SECS_PER_MINUTE) as usize)
            .saturating_mul(SHARE_CAPACITY_HEADROOM)
    }

    /// The script the pool's share of a block pays: the pool's, while a pool configuration
    /// is held, and `mining.pool_address`'s otherwise.
    pub fn payout_script<'a>(&'a self, pool: Option<&'a ClientConfig>) -> &'a [u8] {
        pool.map_or(&self.pool_output_script, |p| &p.payout_script)
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

    /// `minimal()` with `extra` added as another top-level section.
    fn with_extra(extra: &str) -> String {
        minimal().replace(
            r#""datum": {"pool_host": "", "pooled_mining_only": false}"#,
            &format!(r#""datum": {{"pool_host": "", "pooled_mining_only": false}}, {extra}"#),
        )
    }

    #[test]
    fn the_startup_checks_refuse_what_the_settings_form_refuses() {
        let over_id = minimal().replace(
            r#""pool_address":"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080""#,
            r#""pool_address":"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "coinbase_unique_id": 65536"#,
        );
        assert!(
            Config::parse(&over_id).unwrap_err().contains("mining.coinbase_unique_id"),
            "an id the job builder would have truncated is refused"
        );

        let zero_port = with_extra(r#""stratum": {"listen_port": 0}"#);
        assert!(Config::parse(&zero_port).unwrap_err().contains("stratum.listen_port"));

        let pooled = |port| {
            minimal().replace(
                r#""pool_host": """#,
                &format!(r#""pool_host": "pool.example", "pool_port": {port}"#),
            )
        };
        assert!(Config::parse(&pooled(0)).unwrap_err().contains("datum.pool_port"));
        assert!(Config::parse(&pooled(28915)).is_ok());
        assert!(Config::parse(&minimal()).is_ok(), "no pool host, so the port is not reached");
    }

    #[test]
    fn vardiff_min_reads_a_hash_count_or_a_legacy_difficulty() {
        let parse =
            |v: &str| Config::parse(&with_extra(&format!(r#""stratum": {{"vardiff_min": {v}}}"#)));
        let notes =
            |c: &Config| c.startup_notes.iter().map(|n| n.message.clone()).collect::<Vec<_>>();

        let c = parse("null").unwrap();
        assert_eq!((c.stratum.vardiff_min, notes(&c).len()), (16384, 0));
        let c = parse(r#""2.2T""#).unwrap();
        assert_eq!((c.stratum.vardiff_min, notes(&c).len()), (512, 0));
        let c = parse("512").unwrap();
        assert_eq!(c.stratum.vardiff_min, 512);
        assert_eq!(
            notes(&c),
            ["stratum.vardiff_min uses legacy integer syntax; use \"2.2T\" instead"]
        );
        let c = parse(r#""4.5T""#).unwrap();
        assert_eq!(c.stratum.vardiff_min, 2048);
        assert_eq!(notes(&c), ["stratum.vardiff_min rounded up to 8.8T"]);
        let c = parse("1000").unwrap();
        assert_eq!(c.stratum.vardiff_min, 512);
        assert_eq!(notes(&c).len(), 2, "{:?}", notes(&c));
        let c = parse("4398046511104").unwrap();
        assert_eq!((c.stratum.vardiff_min, notes(&c).len()), (1024, 0), "above i32::MAX: hashes");
        for bad in [r#""1.2Z""#, "0", r#""4e12""#, "[]"] {
            assert!(parse(bad).unwrap_err().contains("stratum.vardiff_min"), "{bad}");
        }
    }

    const KEY: &str = "f21f2f0ef0aa1970468f22bad9bb7f4535146f8e4a8f646bebc93da3d89b1406f40d032f09a417d94dc068055df654937922d2c89522e3e8f6f0e649de473003";

    /// `minimal()` pooled, with `fallbacks` as the `datum.fallback_pools` array.
    fn with_fallbacks(fallbacks: &str) -> String {
        minimal().replace(
            r#""pool_host": """#,
            &format!(r#""pool_host": "pool.example", "fallback_pools": {fallbacks}"#),
        )
    }

    #[test]
    fn the_pools_are_the_configured_pool_then_each_fallback_in_order() {
        let c = Config::parse(&with_fallbacks(&format!(
            r#"[{{"pool_host": "b.example", "pool_pubkey": "{KEY}", "pool_url": "https://b"}},
                {{"pool_host": "c.example", "pool_port": 1, "pool_pubkey": "{KEY}"}}]"#
        )))
        .unwrap();
        let addresses: Vec<String> = c.pools.iter().map(Pool::address).collect();
        assert_eq!(addresses, ["pool.example:28915", "b.example:28915", "c.example:1"]);
        assert_eq!(c.pools[1].pool_url, "https://b");
        assert_eq!(c.pools[2].pool_url, "");
        assert_eq!(c.pools[0].pool_pubkey, Pool::default().pool_pubkey);
        assert!(c.startup_notes.is_empty(), "{:?}", c.startup_notes);

        let c = Config::parse(&with_fallbacks("[]")).unwrap();
        assert_eq!(c.pools.len(), 1);
        assert!(Config::parse(&minimal()).unwrap().pools.is_empty(), "non-pooled");
    }

    #[test]
    fn a_fallback_pool_is_checked_as_the_configured_pool_is() {
        for (fallback, must) in [
            (
                format!(r#"{{"pool_host": "", "pool_pubkey": "{KEY}"}}"#),
                "datum.fallback_pools[0].pool_host is empty",
            ),
            (
                r#"{"pool_host": "b.example", "pool_pubkey": "abc"}"#.to_string(),
                "datum.fallback_pools[0].pool_pubkey",
            ),
            (
                format!(r#"{{"pool_host": "b.example", "pool_port": 0, "pool_pubkey": "{KEY}"}}"#),
                "datum.fallback_pools[0].pool_port",
            ),
            (
                format!(r#"{{"pool_host": "b.example", "pool_pubkey": "{KEY}", "pool_url": "b"}}"#),
                "datum.fallback_pools[0].pool_url",
            ),
        ] {
            let e = Config::parse(&with_fallbacks(&format!("[{fallback}]"))).unwrap_err();
            assert!(e.contains(must), "{fallback}: {e}");
            let ok = format!(r#"{{"pool_host": "a.example", "pool_pubkey": "{KEY}"}}"#);
            let e = Config::parse(&with_fallbacks(&format!("[{ok}, {fallback}]"))).unwrap_err();
            let second = must.replace("[0]", "[1]");
            assert!(e.contains(&second), "{fallback}: {e}");
        }
        let twice = format!(r#"{{"pool_host": "pool.example", "pool_pubkey": "{KEY}"}}"#);
        let e = Config::parse(&with_fallbacks(&format!("[{twice}]"))).unwrap_err();
        assert!(e.contains("datum.fallback_pools[0] names pool.example:28915 again"), "{e}");
        let defaulted = minimal().replace(r#""pool_host": "", "#, r#""fallback_pools": [{}], "#);
        let e = Config::parse(&defaulted).unwrap_err();
        assert!(e.contains("names datum-beta1.mine.ocean.xyz:28915 again"), "{e}");
    }

    #[test]
    fn a_datum_section_without_pool_keys_names_the_ocean_pool() {
        let text = minimal().replace(r#""pool_host": "", "#, "");
        let c = Config::parse(&text).unwrap();
        assert_eq!(c.pools.len(), 1);
        assert_eq!(c.pools[0].address(), "datum-beta1.mine.ocean.xyz:28915");
        assert_eq!(c.pools[0].pool_pubkey, Pool::default().pool_pubkey);
        assert_eq!(c.datum.protocol_job_slots, 256, "the other keys keep their defaults");
    }

    #[test]
    fn fallback_pools_without_a_pool_host_are_reported_and_ignored() {
        let text = minimal().replace(
            r#""pool_host": """#,
            &format!(r#""pool_host": "", "fallback_pools": [{{"pool_host": "b.example", "pool_pubkey": "{KEY}"}}]"#),
        );
        let c = Config::parse(&text).unwrap();
        assert!(c.pools.is_empty());
        assert_eq!(c.startup_notes.len(), 1);
        assert!(c.startup_notes[0].message.contains("datum.fallback_pools is ignored"));
    }

    #[test]
    fn parses_the_minimal_file_with_defaults() {
        let c = Config::parse(&minimal()).unwrap();
        assert_eq!(c.stratum.listen_port, 23334);
        assert_eq!(c.stratum.vardiff_min, 16384);
        assert_eq!(c.api.miner_listen_port, 8000);
        assert_eq!(c.bitcoind.work_update_seconds, 40);
        assert!(!c.datum.pooled_mining_only);
    }

    #[test]
    fn the_pool_url_is_empty_unless_set() {
        assert_eq!(Config::parse(&minimal()).unwrap().datum.pool.pool_url, "");
        let text = minimal().replace(
            "\"pooled_mining_only\": false",
            "\"pooled_mining_only\": false, \"pool_url\": \"https://pool.example\"",
        );
        assert_eq!(Config::parse(&text).unwrap().datum.pool.pool_url, "https://pool.example");
    }

    #[test]
    fn a_pool_url_must_be_a_web_url() {
        let with_url = |url: &str| {
            minimal().replace(
                "\"pooled_mining_only\": false",
                &format!("\"pooled_mining_only\": false, \"pool_url\": \"{url}\""),
            )
        };
        for good in ["https://pool.example", "HTTP://pool.example/x", ""] {
            assert!(Config::parse(&with_url(good)).is_ok(), "{good}");
        }
        for bad in ["javascript:alert(1)", "data:text/html,x", "pool.example", "ftp://x"] {
            let e = Config::parse(&with_url(bad)).unwrap_err();
            assert!(e.contains("datum.pool_url"), "{bad}: {e}");
        }
    }

    #[test]
    fn an_rpcurl_without_a_web_scheme_is_refused() {
        for bad in ["127.0.0.1:18443", "ftp://127.0.0.1:18443", "http://"] {
            let text = minimal().replace("http://127.0.0.1:18443", bad);
            let e = Config::parse(&text).unwrap_err();
            assert!(e.contains("bitcoind.rpcurl"), "{bad}: {e}");
        }
    }

    #[test]
    fn the_pool_timeout_and_the_share_rate_have_upper_bounds() {
        let datum = |timeout: u64| {
            minimal().replace(
                "\"pooled_mining_only\": false",
                &format!("\"pooled_mining_only\": false, \"protocol_global_timeout\": {timeout}"),
            )
        };
        assert!(Config::parse(&datum(MAX_PROTOCOL_GLOBAL_TIMEOUT_SECS)).is_ok());
        for over in [MAX_PROTOCOL_GLOBAL_TIMEOUT_SECS + 1, u64::MAX] {
            let e = Config::parse(&datum(over)).unwrap_err();
            assert!(e.contains("datum.protocol_global_timeout must be at most"), "{e}");
        }

        let rate =
            |n: u64| with_extra(&format!(r#""stratum": {{"vardiff_target_shares_min": {n}}}"#));
        let c = Config::parse(&rate(MAX_VARDIFF_TARGET_SHARES_MIN)).unwrap();
        let target_ms = 60_000 / c.stratum.vardiff_target_shares_min;
        assert!(target_ms / MIN_VARDIFF_QUICKDIFF_DELTA > 0 && target_ms / 2 > 0);
        let e = Config::parse(&rate(MAX_VARDIFF_TARGET_SHARES_MIN + 1)).unwrap_err();
        assert!(e.contains("stratum.vardiff_target_shares_min must be at most"), "{e}");
        let e = Config::parse(&rate(u64::MAX)).unwrap_err();
        assert!(e.contains("stratum.vardiff_target_shares_min"), "{e}");
    }

    #[test]
    fn username_modifiers_are_checked() {
        let text = minimal().replace(
            "\"datum\":",
            "\"stratum\": {\"username_modifiers\": {\"half\": {\"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080\": 0.5}}}, \"datum\":",
        );
        let c = Config::parse(&text).unwrap();
        assert_eq!(c.startup_notes.len(), 1);
        assert!(
            c.startup_notes[0].message.contains("not distribute 50% of shares"),
            "{}",
            c.startup_notes[0].message
        );
        let text = minimal().replace(
            "\"datum\":",
            "\"stratum\": {\"username_modifiers\": {\"bad\": {\"\": -1}}}, \"datum\":",
        );
        assert!(Config::parse(&text).unwrap_err().contains("negative"));
    }

    /// Both the modifier names and the addresses under one are written in an order the
    /// alphabet does not give, so each assertion fails if `serde_json` is ever built without
    /// `preserve_order`: its `Map` is then a `BTreeMap` and sorts both. The address order is
    /// what `username::apply_modifier` reads to give each address its selector range, so
    /// sorting the ranges would pay a different address for the same share.
    #[test]
    fn username_modifier_ranges_keep_the_file_order() {
        assert!(ZED < AMY, "the file order below must not be the sorted order");
        let text = minimal().replace(
            "\"datum\":",
            &format!(
                "\"stratum\": {{\"username_modifiers\": {{\"z\": {{\"{AMY}\": 0.1, \"{ZED}\": 0.9}}, \"a\": {{\"\": 1}}}}}}, \"datum\":"
            ),
        );
        let c = Config::parse(&text).unwrap();
        let names: Vec<&str> =
            c.stratum.username_modifiers.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, ["z", "a"]);
        let addrs: Vec<&str> =
            c.stratum.username_modifiers[0].ranges.iter().map(|r| r.address.as_str()).collect();
        assert_eq!(addrs, [AMY, ZED]);
    }

    const ZED: &str = "bcrt1q5xs6rgdp5xs6rgdp5xs6rgdp5xs6rgdpa854mc";
    const AMY: &str = "bcrt1qk2et9v4jk2et9v4jk2et9v4jk2et9v4jldyv0a";

    #[test]
    fn a_username_modifier_address_that_cannot_be_paid_is_refused() {
        let text = minimal().replace(
            "\"datum\":",
            &format!(
                "\"stratum\": {{\"username_modifiers\": {{\"z\": {{\"{ZED}\": 0.5, \"bcrt1qzed\": 0.5}}}}}}, \"datum\":"
            ),
        );
        let e = Config::parse(&text).unwrap_err();
        assert!(e.contains("stratum.username_modifiers.z.bcrt1qzed"), "{e}");
    }

    #[test]
    fn a_username_modifier_that_is_not_an_object_of_numbers_is_refused() {
        for (bad, must) in [
            ("{\"x\": 1}", "must be an object"),
            ("{\"x\": {\"bcrt1qzed\": \"half\"}}", "must be a number"),
        ] {
            let text = minimal().replace(
                "\"datum\":",
                &format!("\"stratum\": {{\"username_modifiers\": {bad}}}, \"datum\":"),
            );
            let e = Config::parse(&text).unwrap_err();
            assert!(e.contains(must), "{bad}: {e}");
        }
    }

    #[test]
    fn work_update_seconds_is_clamped() {
        let text = minimal().replace("\"rpcurl\"", "\"work_update_seconds\": 1, \"rpcurl\"");
        let c = Config::parse(&text).unwrap();
        assert_eq!(c.bitcoind.work_update_seconds, 5);
    }

    #[test]
    fn the_share_capacity_follows_max_clients_and_not_the_thread_settings() {
        let stratum = |extra: &str| {
            let text = with_extra(&format!(r#""stratum": {{{extra}}}"#));
            Config::parse(&text).unwrap_or_else(|e| panic!("{extra}: {e}"))
        };
        let defaults = Config::parse(&minimal()).unwrap();
        assert_eq!(defaults.stratum.max_clients, 1024);
        assert_eq!(defaults.stratum.share_stale_seconds, 120);
        assert_eq!(defaults.shares_in_stale_window(), 1024 * 8 * 2 * SHARE_CAPACITY_HEADROOM);

        // The same client limit spread over the thread settings two ways. Both bound the same
        // one queue and one duplicate-share table, so both must size them the same.
        let wide =
            stratum(r#""max_clients": 1024, "max_clients_per_thread": 128, "max_threads": 8"#);
        let narrow =
            stratum(r#""max_clients": 1024, "max_clients_per_thread": 1024, "max_threads": 1"#);
        assert_eq!(wide.shares_in_stale_window(), narrow.shares_in_stale_window());

        let half =
            stratum(r#""max_clients": 512, "max_clients_per_thread": 512, "max_threads": 1"#);
        assert_eq!(half.shares_in_stale_window() * 2, wide.shares_in_stale_window());
    }
}
