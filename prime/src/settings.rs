//! Turning the options into what each part reads: the server's own settings, the ledger's window
//! rule and split policy, and the share policy a share is checked against.

use crate::cli::Options;
use crate::ledger::WindowRule;
use crate::ledger::split::{PublicGateway, SplitPolicy};
use crate::payout;
use crate::verify::SharePolicy;
use log::warn;
use ratum::datum::messages::config::{ClientConfig, MAX_COINBASE_TAG_LEN};
use ratum::rpc;
use std::fmt::Display;
use std::path::PathBuf;
use std::time::Duration;

const MAX_FEE_BPS: u16 = 10000;
const DEFAULT_POLL_SECS: f64 = 0.5;
const DEFAULT_MIN_DIFFICULTY: u64 = 16384;
const DEFAULT_MAX_CONNECTIONS: usize = 1024;
const DEFAULT_MAX_CONNECTIONS_PER_IP: usize = 32;
const DEFAULT_LISTEN: &str = "0.0.0.0:28915";
const DEFAULT_MOTD: &str = "RATUM Prime";
const DEFAULT_WINDOW_MULTIPLE: f64 = 8.0;
/// The id written in every coinbase's scriptSig and every resume token; a gateway resumes only
/// under a nonzero one.
const PRIME_ID: u64 = 1;
const KEY_FILE: &str = "ratum-prime.key";
/// The hashrate history in a data directory. The samples are of the pool as a whole, not of
/// one chain, so the name carries no chain and a history older than a day is discarded when
/// it is read back.
const HASHRATE_FILE: &str = "hashrate.json";

/// The settings the server itself reads. What the ledger reads is resolved into its
/// `WindowRule` and `SplitPolicy`, and what the share verifier reads into `SharePolicy` (see
/// `share_policy`) instead, so no value is held twice.
pub struct Settings {
    pub listen: String,
    pub stats_listen: Option<String>,
    pub data_dir: Option<PathBuf>,
    pub motd: String,
    pub require_v3: bool,
    pub max_connections: usize,
    pub max_connections_per_ip: usize,
    pub ledger_keep_shares: Option<u64>,
    pub poll: Duration,
}

pub struct Resolved {
    pub settings: Settings,
    pub window: WindowRule,
    pub split: SplitPolicy,
}

pub fn resolve(o: &Options) -> Result<Resolved, String> {
    let public_gateway = public_gateway(o)?;
    let settings = Settings {
        listen: o.listen.clone().unwrap_or_else(|| DEFAULT_LISTEN.to_string()),
        stats_listen: o.stats_listen.clone(),
        data_dir: o.data_dir.clone().map(PathBuf::from),
        motd: o.motd.clone().unwrap_or_else(|| DEFAULT_MOTD.to_string()),
        require_v3: o.require_v3.unwrap_or(false),
        max_connections: valid_or(
            o.max_connections,
            DEFAULT_MAX_CONNECTIONS,
            "--max-connections",
            "a positive number",
            |n| *n > 0,
        )?,
        max_connections_per_ip: valid_or(
            o.max_connections_per_ip,
            DEFAULT_MAX_CONNECTIONS_PER_IP,
            "--max-connections-per-ip",
            "a positive number",
            |n| *n > 0,
        )?,
        ledger_keep_shares: valid(
            o.ledger_keep_shares,
            "--ledger-keep-shares",
            "at least 1",
            |n| *n >= 1,
        )?,
        poll: poll_interval(o.poll)?,
    };
    let window = WindowRule {
        multiple: valid_or(
            o.window,
            DEFAULT_WINDOW_MULTIPLE,
            "--window",
            "a positive number",
            |n| n.is_finite() && *n > 0.0,
        )?,
    };
    let split = SplitPolicy {
        fee_bps: valid_or(
            o.fee_bps,
            0,
            "--fee-bps",
            &format!(
                "basis points from 0 to {MAX_FEE_BPS} (a fee of at most {}%)",
                f64::from(MAX_FEE_BPS) / 100.0
            ),
            |n| *n <= MAX_FEE_BPS,
        )?,
        public_gateway,
    };
    Ok(Resolved { settings, window, split })
}

/// What a share is checked against on `chain`, the chain the node reported at startup (none
/// when it did not answer): the share options, the pool's payout script, and the chain whose
/// address prefixes `--payout-address` and every miner's identity carry.
pub fn share_policy(o: &Options, chain: Option<rpc::Chain>) -> Result<SharePolicy, String> {
    Ok(SharePolicy {
        config: ClientConfig {
            payout_script: payout_script(o, chain)?,
            prime_id: PRIME_ID,
            coinbase_tag: coinbase_tag(o.coinbase_tag.clone().unwrap_or_default())?,
            min_difficulty: valid_or(
                o.min_diff,
                DEFAULT_MIN_DIFFICULTY,
                "--min-diff",
                "a power of two",
                |n| n.is_power_of_two(),
            )?,
            v3: None,
        },
        chain,
    })
}

impl Settings {
    pub fn datum_port(&self) -> u16 {
        self.listen.rsplit_once(':').and_then(|(_, p)| p.parse().ok()).unwrap_or(0)
    }

    /// The pool's signing key: `ratum-prime.key` in the data directory, or in the working
    /// directory without one.
    pub fn key_path(&self) -> PathBuf {
        self.data_dir.as_ref().map_or_else(|| PathBuf::from(KEY_FILE), |dir| dir.join(KEY_FILE))
    }

    /// Where the stats interface keeps its hashrate history, so a restart does not empty it:
    /// a file in the data directory, or none when the pool has no data directory.
    pub fn hashrate_path(&self) -> Option<PathBuf> {
        self.data_dir.as_ref().map(|dir| dir.join(HASHRATE_FILE))
    }
}

fn coinbase_tag(tag: String) -> Result<String, String> {
    if tag.len() > MAX_COINBASE_TAG_LEN {
        return Err(format!(
            "--coinbase-tag must be at most {MAX_COINBASE_TAG_LEN} bytes, not {}; it is pushed into \
             every pooled coinbase's scriptSig ahead of the miner's secondary tag",
            tag.len()
        ));
    }
    if tag.contains('\0') {
        return Err("--coinbase-tag must not hold a NUL byte: a gateway reads the tag up to the \
                    first NUL and pushes only that, so the pool would not find its own tag in \
                    the coinbases it verifies"
            .to_string());
    }
    Ok(tag)
}

/// The gateway `--public-gateway-tag` names and the fee `--public-gateway-fee-bps` and
/// `--public-gateway-fee-subsidy-bps` set on its shares' work.
fn public_gateway(o: &Options) -> Result<Option<PublicGateway>, String> {
    let bps = |value: Option<u16>, flag: &str, what: &str| {
        let max = ratum::BASIS_POINTS_PER_UNIT;
        valid_or(value, 0, flag, &format!("basis points from 0 to {max}: {what}"), |n| {
            u64::from(*n) <= max
        })
    };
    let fee_bps = bps(
        o.public_gateway_fee_bps,
        "--public-gateway-fee-bps",
        "the fee on the work of shares carrying --public-gateway-tag",
    )?;
    let subsidy_bps = bps(
        o.public_gateway_fee_subsidy_bps,
        "--public-gateway-fee-subsidy-bps",
        "the portion of the public gateway fee's work reassigned to miners on their own gateways",
    )?;
    if subsidy_bps > 0 && fee_bps == 0 {
        return Err(
            "--public-gateway-fee-subsidy-bps needs --public-gateway-fee-bps above 0: the \
             subsidy is a portion of that fee's work"
                .into(),
        );
    }
    let tag = o.public_gateway_tag.clone().filter(|t| !t.is_empty());
    match (&tag, fee_bps) {
        (None, 0) => {}
        (None, _) => {
            return Err("--public-gateway-fee-bps needs --public-gateway-tag, the secondary \
                 coinbase tag (mining.coinbase_tag_secondary) of the public gateway; without it no \
                 share can be told apart from the public gateway's"
                .into());
        }
        (Some(t), _) if t.len() > MAX_COINBASE_TAG_LEN => {
            return Err(format!(
                "--public-gateway-tag must be at most {MAX_COINBASE_TAG_LEN} bytes, not {}",
                t.len()
            ));
        }
        (Some(_), 0) => warn!(
            "--public-gateway-tag is set but --public-gateway-fee-bps is 0, so no fee is \
             charged and the tag only separates own-gateway work in /stats.json"
        ),
        (Some(_), _) => {}
    }
    Ok(tag.map(|tag| PublicGateway { tag, fee_bps, subsidy_bps }))
}

fn poll_interval(secs: Option<f64>) -> Result<Duration, String> {
    const MAX_SECS: f64 = ratum::SECS_PER_HOUR as f64;
    valid_or(
        secs,
        DEFAULT_POLL_SECS,
        "--poll",
        &format!("a positive number of seconds up to {MAX_SECS:.0}"),
        |n| n.is_finite() && *n > 0.0 && *n <= MAX_SECS,
    )
    .map(Duration::from_secs_f64)
}

/// The node's client: the pool reads the chain, the tip and the block template from the node
/// and submits every block it finds to it. The credential is `--rpc-cookie`, or the
/// `user:password@` in `--rpc`.
pub fn connect_node(o: &Options) -> Result<rpc::Client, String> {
    let Some(url) = &o.rpc else {
        return Err("--rpc is required: the pool reads the chain, the tip and the block template \
             from the node and submits every block it finds to it"
            .into());
    };
    rpc::Client::new(url, "", "", o.rpc_cookie.as_deref().map(PathBuf::from))
        .map_err(|e| format!("--rpc: {e}"))
}

/// The pool's payout script: `--payout-address` decoded as an address of `chain`.
fn payout_script(o: &Options, chain: Option<rpc::Chain>) -> Result<Vec<u8>, String> {
    let Some(address) = &o.payout_address else {
        return Err("--payout-address is required: the gateway reserves a coinbase output for \
             it on every job, and it receives the value of every fallback case (a miner's \
             identity it cannot pay, an empty window)"
            .into());
    };
    payout::address_script(address, chain).ok_or_else(|| {
        format!("--payout-address {address:?} is {}", payout::unpayable_reason(chain))
    })
}

fn valid_or<T: Display>(
    value: Option<T>,
    default: T,
    flag: &str,
    must_be: &str,
    ok: impl Fn(&T) -> bool,
) -> Result<T, String> {
    Ok(valid(value, flag, must_be, ok)?.unwrap_or(default))
}

fn valid<T: Display>(
    value: Option<T>,
    flag: &str,
    must_be: &str,
    ok: impl Fn(&T) -> bool,
) -> Result<Option<T>, String> {
    match value {
        Some(v) if !ok(&v) => Err(format!("{flag} must be {must_be}, got {v}")),
        value => Ok(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REGTEST_ADDRESS: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    const MAIN_ADDRESS: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

    fn refused(o: Options, flag: &str) {
        let e = resolve(&o).err().unwrap_or_else(|| panic!("{flag} accepted"));
        assert!(e.contains(flag), "{flag}: {e}");
    }

    /// `share_policy` over `o` paying `MAIN_ADDRESS`, with no chain read.
    fn policy(o: Options) -> Result<SharePolicy, String> {
        share_policy(&Options { payout_address: Some(MAIN_ADDRESS.into()), ..o }, None)
    }

    #[test]
    fn the_defaults_resolve() {
        let Resolved { settings, window, split } = resolve(&Options::default()).unwrap();
        assert_eq!(settings.listen, DEFAULT_LISTEN);
        assert_eq!(window, WindowRule { multiple: DEFAULT_WINDOW_MULTIPLE });
        assert_eq!(split.fee_bps, 0);
        assert!(split.public_gateway.is_none());
        let policy = policy(Options::default()).unwrap();
        assert_eq!(policy.config.min_difficulty, 16384);
        assert_eq!(policy.config.prime_id, PRIME_ID);
    }

    #[test]
    fn a_data_directory_holds_the_key_and_the_hashrate_history() {
        let in_dir = resolve(&Options { data_dir: Some("/pool".into()), ..Default::default() })
            .unwrap()
            .settings;
        assert_eq!(in_dir.key_path(), PathBuf::from("/pool/ratum-prime.key"));
        assert_eq!(in_dir.hashrate_path(), Some(PathBuf::from("/pool/hashrate.json")));
        let no_dir = resolve(&Options::default()).unwrap().settings;
        assert_eq!(no_dir.key_path(), PathBuf::from("ratum-prime.key"));
        assert_eq!(no_dir.hashrate_path(), None, "without a data directory nothing is written");
    }

    #[test]
    fn a_value_out_of_its_range_is_refused_with_its_flag() {
        refused(Options { fee_bps: Some(MAX_FEE_BPS + 1), ..Default::default() }, "--fee-bps");
        refused(
            Options { public_gateway_fee_bps: Some(10_001), ..Default::default() },
            "--public-gateway-fee-bps",
        );
        refused(
            Options { public_gateway_fee_subsidy_bps: Some(10_001), ..Default::default() },
            "--public-gateway-fee-subsidy-bps",
        );
        refused(Options { poll: Some(0.0), ..Default::default() }, "--poll");
        refused(Options { max_connections: Some(0), ..Default::default() }, "--max-connections");
        refused(
            Options { ledger_keep_shares: Some(0), ..Default::default() },
            "--ledger-keep-shares",
        );
        refused(Options { window: Some(f64::NAN), ..Default::default() }, "--window");
    }

    #[test]
    fn the_public_gateway_fee_requires_its_tag_and_the_subsidy_requires_the_fee() {
        refused(
            Options { public_gateway_fee_subsidy_bps: Some(5_000), ..Default::default() },
            "--public-gateway-fee-subsidy-bps needs --public-gateway-fee-bps",
        );
        refused(
            Options { public_gateway_fee_bps: Some(200), ..Default::default() },
            "--public-gateway-fee-bps needs --public-gateway-tag",
        );
        refused(
            Options {
                public_gateway_fee_bps: Some(200),
                public_gateway_tag: Some("x".repeat(MAX_COINBASE_TAG_LEN + 1)),
                ..Default::default()
            },
            "--public-gateway-tag must be at most",
        );
        let public = |fee_bps: Option<u16>| {
            resolve(&Options {
                public_gateway_fee_bps: fee_bps,
                public_gateway_fee_subsidy_bps: fee_bps.map(|_| 7_500),
                public_gateway_tag: Some("public".into()),
                ..Default::default()
            })
            .unwrap()
            .split
            .public_gateway
        };
        assert_eq!(
            public(Some(200)),
            Some(PublicGateway { tag: "public".into(), fee_bps: 200, subsidy_bps: 7_500 })
        );
        assert_eq!(
            public(None),
            Some(PublicGateway { tag: "public".into(), fee_bps: 0, subsidy_bps: 0 }),
            "a tag without a fee still separates own-gateway work"
        );
    }

    #[test]
    fn the_share_policy_refuses_a_bad_tag_or_difficulty() {
        let long_tag = Some("x".repeat(MAX_COINBASE_TAG_LEN + 1));
        let e = policy(Options { coinbase_tag: long_tag, ..Default::default() }).unwrap_err();
        assert!(e.contains("--coinbase-tag"), "{e}");
        let nul_tag = Some("RAT\0UM".to_string());
        let e = policy(Options { coinbase_tag: nul_tag, ..Default::default() }).unwrap_err();
        assert!(e.contains("--coinbase-tag") && e.contains("NUL"), "{e}");
        let e = policy(Options { min_diff: Some(3), ..Default::default() }).unwrap_err();
        assert!(e.contains("--min-diff"), "{e}");
    }

    #[test]
    fn the_payout_is_an_address_of_the_nodes_chain() {
        let payout = |address: Option<&str>| Options {
            payout_address: address.map(str::to_string),
            ..Default::default()
        };
        let regtest = Some(rpc::Chain::Regtest);
        let none = share_policy(&payout(None), regtest);
        assert!(none.unwrap_err().contains("is required"));

        let paid = share_policy(&payout(Some(REGTEST_ADDRESS)), regtest).unwrap();
        assert_eq!(&paid.config.payout_script[..2], &[0x00, 0x14]);
        assert_eq!(paid.chain, regtest);
        let e = share_policy(&payout(Some(MAIN_ADDRESS)), regtest).unwrap_err();
        assert!(e.contains("is not a P2PKH, P2SH, P2WPKH, P2WSH or P2TR address of chain regtest"));
        assert!(
            share_policy(&payout(Some(MAIN_ADDRESS)), None).is_ok(),
            "a pool that read no chain at startup accepts every chain's prefixes"
        );
        assert!(connect_node(&Options::default()).unwrap_err().contains("--rpc is required"));
    }
}
