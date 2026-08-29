//! The command line (clap) and the configuration file, and the helpers `main` resolves each
//! setting with. clap owns tokenization, `--help`/`--version`, and the refusals for an
//! unknown flag or a flag without its value; the file is parsed by `ratum_prime::config`. A setting
//! given on the command line overrides the same setting written in the file. `main` applies
//! each default and validates each meaning, so the messages naming a bad value are in this module.

use clap::Parser;
use log::warn;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Every setting as it may be given on the command line. Each is a raw string so its absence
/// is distinguishable from its default (which lets it override the file) and so `main` can
/// parse and validate it with a message that names the constraint. The field names are the
/// `--kebab-case` flags, matching the file's keys.
#[derive(Parser, Debug)]
#[command(
    name = "ratum-prime",
    version = ratum::VERSION,
    about = "DATUM Prime: the pool server of the DATUM protocol",
    // So a value like "-1" after a numeric flag is taken as the value rather than parsed
    // as a flag; "-v" and other non-numbers are still rejected as unknown arguments.
    allow_negative_numbers = true,
    // A flag given more than once takes its last value rather than being refused, which lets
    // a command-line value override the same setting written in the config file.
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
    pub data_dir: Option<String>,
    #[arg(long)]
    pub config: Option<String>,
    #[arg(long)]
    pub key: Option<String>,
    #[arg(long)]
    pub motd: Option<String>,
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
    pub activation_height: Option<String>,
    #[arg(long)]
    pub headline: Option<String>,
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
    /// Print the ledger (`--ledger` or `--data-dir`) as `<unix-seconds> <difficulty>
    /// <identity> <share-hash>` lines, oldest first, and exit. The pool must not be running,
    /// since it holds the ledger's exclusive lock.
    #[arg(long)]
    pub dump_ledger: bool,
}

/// The command line and the file it named, ready for `main` to resolve each setting from.
pub(crate) struct Loaded {
    pub cli: Cli,
    pub file: ratum_prime::config::Config,
}

/// Parse the command line, then read the configuration file it points at: `--config` names
/// one, or `--data-dir` holds `ratum.toml`. A file named by `--config` that is not there
/// stops startup; an absent one in the data directory does not.
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

/// Print the reason a value is refused and exit with the argument-error code, so `RUST_LOG`
/// does not hide it.
pub(crate) fn refuse(flag: &str, must_be: &str, got: &str) -> ! {
    eprintln!("{flag} must be {must_be}, got {got}");
    std::process::exit(2);
}

/// Resolve a required setting: the command-line value if given, else the file's, else
/// `default`. A value that does not parse as `T` or does not satisfy `ok` is refused with
/// `must_be` naming the constraint.
pub(crate) fn resolve<T: FromStr>(
    cli: Option<&str>,
    file: Option<T>,
    default: T,
    flag: &str,
    must_be: &str,
    ok: impl Fn(&T) -> bool,
) -> T {
    match cli {
        Some(s) => {
            let value = s.parse::<T>().unwrap_or_else(|_| refuse(flag, must_be, &format!("{s:?}")));
            if ok(&value) { value } else { refuse(flag, must_be, &format!("{s:?}")) }
        }
        None => match file {
            Some(value) if ok(&value) => value,
            Some(_) => refuse(flag, must_be, "the configured value"),
            None => default,
        },
    }
}

/// Resolve an optional setting the same way, returning `None` when it is given nowhere.
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

/// A string setting: the command-line value, else the file's, else `default`.
pub(crate) fn resolve_str(cli: Option<String>, file: Option<String>, default: &str) -> String {
    cli.or(file).unwrap_or_else(|| default.to_string())
}

/// A file holding a password is only better than a command line if it is not readable by
/// everyone. The pool does not change the permissions; it logs a warning.
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
