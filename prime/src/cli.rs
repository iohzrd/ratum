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
    /// Comma-separated user-agent prefixes a gateway's hello must match (e.g.
    /// "ratum-gateway/"). Empty (the default) accepts every agent.
    #[arg(long)]
    pub allow_agent: Option<String>,
    /// Refuse a share whose coinbase pays none of the outputs the coinbaser dictated for
    /// its job ("true", the default, or "false"). See RejectReason::NoSplit.
    #[arg(long)]
    pub require_split: Option<String>,
    /// Refuse at hello any gateway that does not use the version 3 protocol (its hello
    /// carries no DRS extension). Bare `--require-v3` means true. Off (the default) serves
    /// version 1 and version 3 gateways; on, every connection is under an
    /// anti-block-withholding assignment, so no client can withhold blocks selectively.
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub require_v3: Option<String>,
    /// Seconds after an anti-block-withholding slot is retired before its key is revealed to
    /// the gateway (1 to 600, default 300). Must exceed the time the gateway keeps
    /// submitting shares on the slot's jobs, `share_stale_seconds + work_update_seconds` in
    /// the C gateway (160 by default, 270 at most; the default covers the most): the
    /// gateway audits every proof it retained on the slot when it receives the reveal. It
    /// holds a proof per share until then, in a cache of 65536, so a longer delay lowers the
    /// share rate one gateway can sustain (about 160 per second at the default, 270 at a
    /// delay of 180, which covers the C default window only).
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
    /// The pool's prime id (1 to 4294967295, default 1): the push every share's coinbase
    /// must carry, and the first eight bytes of a version 3 resume token. Zero is refused:
    /// the C gateway keeps no resume token under a zero prime id, so it would discard its
    /// queued shares and retained proofs on every reconnect.
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
    /// Print the ledger (`--ledger` or `--data-dir`) as `<unix-seconds> <difficulty>
    /// <identity> <share-hash>` lines, oldest first, and exit. The pool must not be running,
    /// since it holds the ledger's exclusive lock.
    #[arg(long)]
    pub dump_ledger: bool,
    /// Mark an owed block (a block whose coinbase paid the pool's payout script value the
    /// window is owed; the hash the pool logged and the stats page shows) settled in the
    /// ledger (`--ledger` or `--data-dir`),
    /// print its record, and exit. Run it after paying the amounts from the pool's wallet.
    /// The pool must not be running, since it holds the ledger's exclusive lock. Without a
    /// hash, `--settle-block list` prints every owed block instead.
    #[arg(long)]
    pub settle_block: Option<String>,
    /// Remove an owed block (the hash the pool logged) from the ledger (`--ledger` or
    /// `--data-dir`), print its record, and exit. For a block that was rejected or
    /// orphaned: the pool's payout script never received its value, so nothing is owed.
    /// The pool must not be running, since it holds the ledger's exclusive lock.
    #[arg(long)]
    pub void_block: Option<String>,
    /// Add an owed record for a block in the ledger's block history (the hash the pool
    /// logged) from `--owed identity=sats` entries, print it, and exit. For a block the pool
    /// accepted before it recorded the dictated outputs a coinbase leaves out, or whose
    /// record was voided by mistake. The entries may not total more than the block's
    /// coinbase paid to the pool's payout script; that figure includes the operator fee,
    /// which is not owed, so the pool's records stay under it by the fee. The pool must not
    /// be running, since it holds the ledger's exclusive lock.
    #[arg(long)]
    pub record_owed: Option<String>,
    /// An `identity=sats` entry for `--record-owed`; repeat it for each identity.
    #[arg(long, value_name = "IDENTITY=SATS")]
    pub owed: Vec<String>,
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
