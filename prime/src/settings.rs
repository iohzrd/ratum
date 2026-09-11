use crate::abw;
use crate::cli::{self, Cli, fatal};
use crate::server::{Resolved, resolve_address};
use log::warn;
use ratum::bitcoin::opcode::OP_RETURN;
use ratum::bitcoin::output_script_size_is_valid;
use ratum::datum::messages::MAX_COINBASE_TAG;
use ratum::rpc;
use ratum_prime::config::Config;
use std::path::PathBuf;
use std::time::Duration;

const DUST_THRESHOLD_P2PKH: u64 = 546;
const MAX_FEE_BPS: u16 = 100;
const DEFAULT_POLL_SECS: f64 = 0.5;
const DEFAULT_MIN_DIFFICULTY: u64 = 16384;
const DEFAULT_MAX_CONNECTIONS: usize = 1024;
const DEFAULT_LISTEN: &str = "0.0.0.0:28915";
const DEFAULT_MOTD: &str = "RATUM Prime";
const DEFAULT_WINDOW_MULTIPLE: f64 = 8.0;

pub(crate) struct Settings {
    pub(crate) listen: String,
    pub(crate) stats_listen: Option<String>,
    pub(crate) advertise_address: Option<String>,
    pub(crate) public_gateway: Option<String>,
    pub(crate) data_dir: Option<PathBuf>,
    pub(crate) key_path: PathBuf,
    pub(crate) motd: String,
    pub(crate) allowed_agents: Vec<String>,
    pub(crate) require_v3: bool,
    pub(crate) abw_reveal_after: Duration,
    pub(crate) min_difficulty: u64,
    pub(crate) max_connections: usize,
    pub(crate) payout: Option<(Payout, String)>,
    pub(crate) coinbase_tag: String,
    pub(crate) prime_id: u32,
    pub(crate) ledger_path: Option<String>,
    pub(crate) ledger_keep: Option<usize>,
    pub(crate) window_multiple: f64,
    pub(crate) window_floor: u128,
    pub(crate) min_payout: u64,
    pub(crate) fee_bps: u16,
    pub(crate) poll: Duration,
    pub(crate) require_split: bool,
    node: NodeCredential,
}

struct NodeCredential {
    url: Option<String>,
    user: String,
    pass: String,
    cookie: Option<String>,
    pass_on_argv: bool,
}

impl Settings {
    pub(crate) fn resolve(c: &Cli, f: Config) -> Self {
        let payout = payout_choice(c, &f);
        let data_dir = c.data_dir.clone().or(f.data_dir).map(PathBuf::from);
        Self {
            listen: cli::resolve_str(c.listen.clone(), f.listen, DEFAULT_LISTEN),
            stats_listen: c.stats_listen.clone().or(f.stats_listen),
            advertise_address: c.advertise_address.clone().or(f.advertise_address),
            public_gateway: c.public_gateway.clone().or(f.public_gateway).map(with_scheme),
            key_path: key_path(c.key.clone().or(f.key), data_dir.as_ref()),
            data_dir,
            motd: cli::resolve_str(c.motd.clone(), f.motd, DEFAULT_MOTD),
            allowed_agents: agent_prefixes(&cli::resolve_str(
                c.allow_agent.clone(),
                f.allow_agent,
                "",
            )),
            require_v3: c.require_v3.or(f.require_v3).unwrap_or(false),
            abw_reveal_after: reveal_after(c.abw_reveal_after, f.abw_reveal_after),
            min_difficulty: cli::resolve(
                c.min_diff,
                f.min_diff,
                DEFAULT_MIN_DIFFICULTY,
                "--min-diff",
                "a power of two",
                |n| n.is_power_of_two(),
            ),
            max_connections: cli::resolve(
                c.max_connections,
                f.max_connections,
                DEFAULT_MAX_CONNECTIONS,
                "--max-connections",
                "a positive number",
                |n| *n > 0,
            ),
            payout,
            coinbase_tag: coinbase_tag(cli::resolve_str(
                c.coinbase_tag.clone(),
                f.coinbase_tag,
                "",
            )),
            prime_id: cli::resolve(
                c.prime_id,
                f.prime_id,
                1,
                "--prime-id",
                "a positive number",
                |n| *n > 0,
            ),
            ledger_path: c.ledger.clone().or(f.ledger),
            ledger_keep: cli::resolve_opt(
                c.ledger_keep,
                f.ledger_keep,
                "--ledger-keep",
                "at least 1",
                |n| *n >= 1,
            ),
            window_multiple: cli::resolve(
                c.window,
                f.window,
                DEFAULT_WINDOW_MULTIPLE,
                "--window",
                "a positive number",
                |n| n.is_finite() && *n > 0.0,
            ),
            window_floor: c.window_floor.or(f.window_floor).unwrap_or(1).max(1),
            min_payout: c.min_payout.or(f.min_payout).unwrap_or(DUST_THRESHOLD_P2PKH),
            fee_bps: cli::resolve(
                c.fee_bps,
                f.fee_bps,
                0,
                "--fee-bps",
                &format!(
                    "basis points from 0 to {MAX_FEE_BPS} (a fee of at most {}%)",
                    f64::from(MAX_FEE_BPS) / 100.0
                ),
                |n| *n <= MAX_FEE_BPS,
            ),
            poll: poll_interval(c.poll, f.poll),
            require_split: c.require_split.or(f.require_split).unwrap_or(true),
            node: NodeCredential {
                url: c.rpc.clone().or(f.rpc),
                user: cli::resolve_str(c.rpc_user.clone(), f.rpc_user, ""),
                pass: cli::resolve_str(c.rpc_pass.clone(), f.rpc_pass, ""),
                cookie: c.rpc_cookie.clone().or(f.rpc_cookie),
                pass_on_argv: c.rpc_pass.is_some(),
            },
        }
    }

    pub(crate) fn connect_node(&self) -> std::io::Result<rpc::Client> {
        self.node.connect()
    }
}

fn coinbase_tag(tag: String) -> String {
    if tag.len() > MAX_COINBASE_TAG {
        fatal!(
            "--coinbase-tag must be at most {MAX_COINBASE_TAG} bytes, not {}; it is pushed into \
             every pooled coinbase's scriptSig ahead of the miner's secondary tag",
            tag.len()
        );
    }
    tag
}

fn agent_prefixes(list: &str) -> Vec<String> {
    list.split(',').map(str::trim).filter(|p| !p.is_empty()).map(str::to_string).collect()
}

fn reveal_after(cli: Option<u64>, file: Option<u64>) -> Duration {
    let range = abw::REVEAL_AFTER_SECS_RANGE;
    let must_be = format!("{} to {} (seconds)", range.start(), range.end());
    Duration::from_secs(cli::resolve(
        cli,
        file,
        abw::DEFAULT_REVEAL_AFTER.as_secs(),
        "--abw-reveal-after",
        &must_be,
        |n| range.contains(n),
    ))
}

fn poll_interval(cli: Option<f64>, file: Option<f64>) -> Duration {
    const MAX_SECS: f64 = ratum::SECS_PER_HOUR as f64;
    Duration::from_secs_f64(cli::resolve(
        cli,
        file,
        DEFAULT_POLL_SECS,
        "--poll",
        &format!("a positive number of seconds up to {MAX_SECS:.0}"),
        |n| n.is_finite() && *n > 0.0 && *n <= MAX_SECS,
    ))
}

fn with_scheme(url: String) -> String {
    if url.starts_with("http://") || url.starts_with("https://") {
        url
    } else {
        format!("https://{url}")
    }
}

fn key_path(named: Option<String>, data_dir: Option<&PathBuf>) -> PathBuf {
    const KEY_FILE: &str = "ratum-prime.key";
    match (named, data_dir) {
        (Some(p), _) => PathBuf::from(p),
        (None, Some(dir)) => dir.join(KEY_FILE),
        (None, None) => PathBuf::from(KEY_FILE),
    }
}

impl NodeCredential {
    fn connect(&self) -> std::io::Result<rpc::Client> {
        if self.pass_on_argv {
            warn!(
                "--rpc-pass puts the node's password in this process's command line, where \
                 any local user can read it; a configuration file and --rpc-cookie do not"
            );
            if self.cookie.is_some() {
                warn!("--rpc-cookie was given as well, and it is the one being used");
            }
        }
        if let Some(path) = &self.cookie {
            match std::fs::read_to_string(path) {
                Ok(text) if text.trim().split_once(':').is_some() => {}
                Ok(_) => fatal!("{path} is not a cookie file: expected user:password"),
                Err(e) => fatal!("could not read the rpc cookie {path}: {e}"),
            }
        }
        let Some(url) = &self.url else {
            fatal!(
                "--rpc is required: without a node the pool cannot resolve a miner's address, \
                 so every block it finds pays --payout-address and no miner at all"
            )
        };
        match &self.cookie {
            Some(path) => rpc::Client::with_cookie(url, PathBuf::from(path)),
            None => rpc::Client::new(url, &self.user, &self.pass),
        }
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Payout {
    Address,
    Script,
}

impl Payout {
    fn flag(self) -> &'static str {
        match self {
            Self::Address => "--payout-address",
            Self::Script => "--payout-script",
        }
    }
}

fn payout_choice(c: &Cli, f: &Config) -> Option<(Payout, String)> {
    let sources = [
        (c.payout_address.as_ref(), c.payout_script.as_ref()),
        (f.payout_address.as_ref(), f.payout_script.as_ref()),
    ];
    for (address, script) in sources {
        match (address, script) {
            (Some(a), None) => return Some((Payout::Address, a.clone())),
            (None, Some(s)) => return Some((Payout::Script, s.clone())),
            (Some(_), Some(_)) => fatal!("give --payout-address or --payout-script, not both"),
            (None, None) => {}
        }
    }
    None
}

pub(crate) fn payout_script(node: &rpc::Client, payout: Option<(Payout, String)>) -> Vec<u8> {
    let Some((kind, value)) = payout else {
        fatal!(
            "--payout-address (or --payout-script) is required: the gateway reserves a \
             coinbase output for it on every job, and it receives the value of every \
             fallback case (an address that does not resolve, a script too long to pay, an \
             empty window, a split that could not be encoded)"
        )
    };
    let script = match kind {
        Payout::Script => match hex::decode(&value) {
            Ok(b) if b.first() == Some(&OP_RETURN) => fatal!(
                "--payout-script starts with OP_RETURN, which would burn every fallback \
                 payment rather than pay it"
            ),
            Ok(b) if !b.is_empty() => b,
            _ => fatal!("--payout-script must be a non-empty hex script, got {value:?}"),
        },
        Payout::Address => match resolve_address(node, &value) {
            Ok(Resolved::Script(b)) => b,
            Ok(Resolved::NoScript) => fatal!("the node gave no scriptPubKey for {value:?}"),
            Ok(Resolved::Invalid) => {
                fatal!("--payout-address {value:?} is not an address this node accepts")
            }
            Err(e) => fatal!("could not resolve --payout-address {value:?}: {e}"),
        },
    };
    if !output_script_size_is_valid(&script) {
        fatal!(
            "{} gives a {}-byte script, which a block carrying it would be rejected for: \
             a coinbase output script may be at most {} bytes",
            kind.flag(),
            script.len(),
            ratum::bitcoin::MAX_OUTPUT_SCRIPT_SIZE
        );
    }
    script
}
