//! The configuration file: the same JSON schema as the C gateway's `datum_gateway_config.json`,
//! so a deployment can swap the binary without changing its file. Every key is optional
//! except the ones the C gateway requires (`bitcoind.rpcurl`, `mining.pool_address`,
//! `mining.blake2b_activation_height`, `mining.blake2b_headline`). Unknown keys are ignored,
//! as the C gateway ignores them.

use serde::Deserialize;

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
    pub blake2b_activation_height: u32,
    pub blake2b_headline: String,
    pub save_submitblocks_dir: String,
}

impl Default for Mining {
    fn default() -> Self {
        Mining {
            pool_address: String::new(),
            coinbase_tag_primary: "DATUM Gateway".into(),
            coinbase_tag_secondary: "DATUM User".into(),
            coinbase_unique_id: 4242,
            blake2b_activation_height: 0,
            blake2b_headline: String::new(),
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
        if m.blake2b_activation_height == 0 {
            return Err("mining.blake2b_activation_height must be set. It is the first height at which a version 2 (BLAKE2b) block is valid on the network being mined.".into());
        }
        if m.blake2b_headline.is_empty() {
            return Err("mining.blake2b_headline must be set. It is the text the network requires in the coinbase of the activation block.".into());
        }
        if m.blake2b_headline.len() > MAX_COINBASE_TAG_SPACE {
            return Err(format!(
                "mining.blake2b_headline is {} bytes; at most {MAX_COINBASE_TAG_SPACE} fit in the coinbase",
                m.blake2b_headline.len()
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
        if self.api.modify_conf {
            self.warn("api.modify_conf is set but the configuration is not editable over HTTP");
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

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal() -> String {
        r#"{
          "bitcoind": {"rpcuser":"u","rpcpassword":"p","rpcurl":"http://127.0.0.1:18443"},
          "mining": {"pool_address":"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
                     "blake2b_activation_height": 20, "blake2b_headline": "x"},
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
    fn refuses_a_missing_activation_height() {
        let text = minimal().replace("\"blake2b_activation_height\": 20,", "");
        let e = Config::parse(&text).unwrap_err();
        assert!(e.contains("blake2b_activation_height"), "{e}");
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
}
