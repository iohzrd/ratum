use clap::Parser;
use log::warn;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Parser, Debug)]
#[command(
    name = "ratum-prime",
    version = ratum::VERSION,
    about = "DATUM Prime: the pool server of the DATUM protocol",
    allow_negative_numbers = true,
    args_override_self = true
)]
pub(crate) struct Cli {
    #[arg(long)]
    pub listen: Option<String>,
    #[arg(long)]
    pub stats_listen: Option<String>,
    #[arg(long)]
    pub advertise_address: Option<String>,
    #[arg(long)]
    pub public_gateway: Option<String>,
    #[arg(long)]
    pub data_dir: Option<String>,
    #[arg(long)]
    pub config: Option<String>,
    #[arg(long)]
    pub key: Option<String>,
    #[arg(long)]
    pub motd: Option<String>,
    #[arg(long)]
    pub allow_agent: Option<String>,
    #[arg(long)]
    pub require_split: Option<String>,
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub require_v3: Option<String>,
    #[arg(long)]
    pub abw_reveal_after: Option<String>,
    #[arg(long)]
    pub min_diff: Option<String>,
    #[arg(long)]
    pub max_connections: Option<String>,
    #[arg(long)]
    pub payout_address: Option<String>,
    #[arg(long)]
    pub payout_script: Option<String>,
    #[arg(long)]
    pub coinbase_tag: Option<String>,
    #[arg(long)]
    pub prime_id: Option<String>,
    #[arg(long)]
    pub ledger: Option<String>,
    #[arg(long)]
    pub ledger_keep: Option<String>,
    #[arg(long)]
    pub window: Option<String>,
    #[arg(long)]
    pub window_floor: Option<String>,
    #[arg(long)]
    pub min_payout: Option<String>,
    #[arg(long)]
    pub fee_bps: Option<String>,
    #[arg(long)]
    pub rpc: Option<String>,
    #[arg(long)]
    pub rpc_user: Option<String>,
    #[arg(long)]
    pub rpc_pass: Option<String>,
    #[arg(long)]
    pub rpc_cookie: Option<String>,
    #[arg(long)]
    pub poll: Option<String>,
    #[arg(long)]
    pub dump_ledger: bool,
    #[arg(long)]
    pub settle_block: Option<String>,
    #[arg(long)]
    pub void_block: Option<String>,
    #[arg(long)]
    pub record_owed: Option<String>,
    #[arg(long, value_name = "IDENTITY=SATS")]
    pub owed: Vec<String>,
}

pub(crate) struct Loaded {
    pub cli: Cli,
    pub file: ratum_prime::config::Config,
}

pub(crate) fn load() -> Loaded {
    let cli = Cli::parse();
    let path = match (&cli.config, &cli.data_dir) {
        (Some(p), _) => Some(PathBuf::from(p)),
        (None, Some(dir)) => Some(PathBuf::from(dir).join("ratum.toml")),
        (None, None) => None,
    };
    let file = match path {
        Some(path) => load_file(&path, cli.config.is_some()),
        None => ratum_prime::config::Config::default(),
    };
    Loaded { cli, file }
}

fn load_file(path: &Path, required: bool) -> ratum_prime::config::Config {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !required => {
            return ratum_prime::config::Config::default();
        }
        Err(e) => {
            eprintln!("cannot read {}: {e}", path.display());
            std::process::exit(2);
        }
    };
    match ratum_prime::config::parse(&text) {
        Ok(c) => {
            warn_if_readable(path, &c);
            c
        }
        Err(e) => {
            eprintln!("{}: {e}", path.display());
            std::process::exit(2);
        }
    }
}

pub(crate) fn refuse(flag: &str, must_be: &str, got: &str) -> ! {
    eprintln!("{flag} must be {must_be}, got {got}");
    std::process::exit(2);
}

pub(crate) fn resolve<T: FromStr>(
    cli: Option<&str>,
    file: Option<T>,
    default: T,
    flag: &str,
    must_be: &str,
    ok: impl Fn(&T) -> bool,
) -> T {
    resolve_opt(cli, file, flag, must_be, ok).unwrap_or(default)
}

pub(crate) fn resolve_opt<T: FromStr>(
    cli: Option<&str>,
    file: Option<T>,
    flag: &str,
    must_be: &str,
    ok: impl Fn(&T) -> bool,
) -> Option<T> {
    match cli {
        Some(s) => {
            let value = s.parse::<T>().unwrap_or_else(|_| refuse(flag, must_be, &format!("{s:?}")));
            if ok(&value) { Some(value) } else { refuse(flag, must_be, &format!("{s:?}")) }
        }
        None => match file {
            Some(value) if ok(&value) => Some(value),
            Some(_) => refuse(flag, must_be, "the configured value"),
            None => None,
        },
    }
}

pub(crate) fn resolve_str(cli: Option<String>, file: Option<String>, default: &str) -> String {
    cli.or(file).unwrap_or_else(|| default.to_string())
}

#[cfg(unix)]
fn warn_if_readable(path: &Path, settings: &ratum_prime::config::Config) {
    use std::os::unix::fs::PermissionsExt as _;
    if !settings.holds_a_secret() {
        return;
    }
    let Ok(mode) = std::fs::metadata(path).map(|m| m.permissions().mode()) else { return };
    if mode & 0o077 != 0 {
        warn!(
            "{} holds a password and is readable by more than its owner (mode {:03o}); \
             chmod 600 it",
            path.display(),
            mode & 0o777
        );
    }
}

#[cfg(not(unix))]
fn warn_if_readable(_path: &Path, _settings: &ratum_prime::config::Config) {}
