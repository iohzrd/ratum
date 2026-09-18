//! The command line and the settings file, which share one field list: every setting can be written
//! in either, and a flag given on the command line overrides the file's value.

use clap::Parser as _;
use log::warn;
use std::path::{Path, PathBuf};

pub const USAGE_EXIT: i32 = 2;

macro_rules! fatal {
    ($($arg:tt)*) => {{
        eprintln!($($arg)*);
        std::process::exit($crate::cli::USAGE_EXIT);
    }};
}

pub(crate) use fatal;

#[derive(Debug, Default, PartialEq, serde::Deserialize, clap::Parser)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
#[command(
    name = "ratum-prime",
    version = crate::VERSION,
    about = "DATUM Prime: the pool server of the DATUM protocol",
    allow_negative_numbers = true,
    args_override_self = true
)]
pub struct Options {
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
    #[serde(skip)]
    pub config: Option<String>,
    #[arg(long)]
    pub key: Option<String>,
    #[arg(long)]
    pub motd: Option<String>,
    #[arg(long)]
    pub allow_agent: Option<String>,
    #[arg(long)]
    pub require_split: Option<bool>,
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    pub require_v3: Option<bool>,
    #[arg(long)]
    pub abw_reveal_after: Option<u64>,
    #[arg(long)]
    pub min_diff: Option<u64>,
    #[arg(long)]
    pub max_connections: Option<usize>,
    #[arg(long)]
    pub payout_address: Option<String>,
    #[arg(long)]
    pub payout_script: Option<String>,
    #[arg(long)]
    pub coinbase_tag: Option<String>,
    #[arg(long)]
    pub prime_id: Option<u32>,
    #[arg(long)]
    pub ledger: Option<String>,
    #[arg(long)]
    pub ledger_keep_shares: Option<u64>,
    #[arg(long)]
    pub window: Option<f64>,
    #[arg(long)]
    pub window_floor: Option<u128>,
    #[arg(long)]
    pub min_payout: Option<u64>,
    #[arg(long)]
    pub fee_bps: Option<u16>,
    #[arg(long)]
    pub public_gateway_fee_bps: Option<u16>,
    #[arg(long)]
    pub public_gateway_fee_subsidy_bps: Option<u16>,
    #[arg(long)]
    pub public_gateway_tag: Option<String>,
    #[arg(long)]
    pub rpc: Option<String>,
    #[arg(long)]
    pub rpc_user: Option<String>,
    #[arg(long)]
    pub rpc_pass: Option<String>,
    #[arg(long)]
    pub rpc_cookie: Option<String>,
    #[arg(long)]
    pub poll: Option<f64>,
    #[arg(long)]
    #[serde(skip)]
    pub dump_ledger: bool,
    #[arg(long)]
    #[serde(skip)]
    pub settle_block: Option<String>,
    #[arg(long)]
    #[serde(skip)]
    pub void_block: Option<String>,
    #[arg(long)]
    #[serde(skip)]
    pub record_owed: Option<String>,
    #[arg(long, value_name = "IDENTITY=SATS")]
    #[serde(skip)]
    pub owed: Vec<String>,
}

impl Options {
    /// The file's settings with every flag given on the command line applied over them.
    /// `self` is the parsed command line and `argv` the arguments it was parsed from. A
    /// payout choice on the command line replaces the file's as a pair, so an address from
    /// one source is never combined with a script from the other.
    pub fn over<I, T>(self, mut file: Self, argv: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        if self.payout_address.is_some() || self.payout_script.is_some() {
            file.payout_address = None;
            file.payout_script = None;
        }
        file.update_from(argv);
        file
    }
}

/// The options on the command line merged over those of the settings file: the file
/// `--config` names, or `ratum.toml` in `--data-dir`.
pub fn load() -> Options {
    let command_line = Options::parse();
    let rpc_pass_on_argv = command_line.rpc_pass.is_some();
    let path = match (&command_line.config, &command_line.data_dir) {
        (Some(p), _) => Some(PathBuf::from(p)),
        (None, Some(dir)) => Some(PathBuf::from(dir).join("ratum.toml")),
        (None, None) => None,
    };
    let file = match path {
        Some(path) => load_file(&path, command_line.config.is_some()),
        None => Options::default(),
    };
    let options = command_line.over(file, std::env::args_os());
    if rpc_pass_on_argv {
        warn!(
            "--rpc-pass puts the node's password in this process's command line, where any \
             local user can read it; a configuration file and --rpc-cookie do not"
        );
        if options.rpc_cookie.is_some() {
            warn!(
                "--rpc-cookie was given as well, but --rpc-user is set, so the user and \
                 password are the credential being used; drop --rpc-user to read the cookie"
            );
        }
    }
    options
}

fn load_file(path: &Path, required: bool) -> Options {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !required => {
            return Options::default();
        }
        Err(e) => fatal!("cannot read {}: {e}", path.display()),
    };
    match toml::from_str(&text) {
        Ok(c) => {
            warn_if_readable(path, &c);
            c
        }
        Err(e) => fatal!("{}: {e}", path.display()),
    }
}

#[cfg(unix)]
fn warn_if_readable(path: &Path, settings: &Options) {
    use std::os::unix::fs::PermissionsExt as _;
    if settings.rpc_pass.is_none() {
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
fn warn_if_readable(_path: &Path, _settings: &Options) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_toml(text: &str) -> Result<Options, toml::de::Error> {
        toml::from_str(text)
    }

    #[test]
    fn settings_parse_into_their_typed_fields() {
        let c = parse_toml(
            "rpc-user = \"ratum\"\nmin-diff = 16384\nwindow = 8.5\n\
             public-gateway-fee-bps = 200\npublic-gateway-fee-subsidy-bps = 7500\n\
             public-gateway-tag = \"public\"\n",
        )
        .unwrap();
        assert_eq!(c.min_diff, Some(16384));
        assert_eq!(c.window, Some(8.5));
        assert_eq!(c.rpc_user, Some("ratum".to_string()));
        assert_eq!(c.public_gateway_fee_bps, Some(200));
        assert_eq!(c.public_gateway_fee_subsidy_bps, Some(7500));
        assert_eq!(c.public_gateway_tag, Some("public".to_string()));
        assert_eq!(c.listen, None, "a setting not written stays unset");
    }

    #[test]
    fn nothing_written_is_nothing_set() {
        assert_eq!(parse_toml("").unwrap(), Options::default());
        assert_eq!(parse_toml("# only a comment\n").unwrap(), Options::default());
    }

    #[test]
    fn a_setting_may_be_annotated() {
        let c = parse_toml(
            "# the smallest share difficulty credited\nmin-diff = 16384  # a power of two\n",
        )
        .unwrap();
        assert_eq!(c.min_diff, Some(16384));
    }

    #[test]
    fn a_value_of_the_wrong_type_is_refused_where_it_is() {
        let e = parse_toml("motd = \"fine\"\nmin-diff = \"soon\"\n").unwrap_err().to_string();
        assert!(e.contains("min-diff"), "{e}");
        assert!(e.contains("line 2"), "{e}");
    }

    #[test]
    fn a_name_the_pool_does_not_have_is_refused() {
        let e = parse_toml("min-dif = 1\n").unwrap_err().to_string();
        assert!(e.contains("min-dif"), "{e}");
        assert!(e.contains("min-diff"), "the ones it does have are named: {e}");
    }

    #[test]
    fn a_configuration_file_cannot_name_another_one() {
        let e = parse_toml("config = \"/etc/other.toml\"\n").unwrap_err().to_string();
        assert!(e.contains("config"), "{e}");
    }

    #[test]
    fn a_configuration_file_cannot_hold_a_ledger_command() {
        for text in [
            "dump-ledger = true\n",
            "settle-block = \"list\"\n",
            "void-block = \"00\"\n",
            "record-owed = \"00\"\n",
            "owed = [\"alice=1\"]\n",
        ] {
            let e = parse_toml(text).expect_err("a command is not a setting").to_string();
            assert!(e.contains("unknown field"), "{text:?}: {e}");
        }
    }

    #[test]
    fn text_that_is_not_settings_is_an_error() {
        for text in ["oops\n", "min-diff = \n", "[section]\nmin-diff = 1\n"] {
            let e = parse_toml(text).expect_err("not settings").to_string();
            assert!(!e.is_empty(), "{text:?}");
        }
    }

    #[test]
    fn a_flag_given_as_well_overrides_the_file_and_the_payout_pair_moves_together() {
        let argv = ["ratum-prime", "--min-diff", "1024", "--payout-address", "cli", "--require-v3"];
        let file = Options {
            min_diff: Some(16384),
            motd: Some("file".into()),
            payout_script: Some("51".into()),
            require_v3: Some(false),
            ..Options::default()
        };
        let merged = Options::parse_from(argv).over(file, argv);
        assert_eq!(merged.min_diff, Some(1024));
        assert_eq!(merged.motd.as_deref(), Some("file"), "a flag not given keeps the file's value");
        assert_eq!(merged.require_v3, Some(true), "a bare flag overrides the file's false");
        assert_eq!(merged.payout_address.as_deref(), Some("cli"));
        assert_eq!(merged.payout_script, None, "the file's payout choice is replaced as a pair");
        assert!(!merged.dump_ledger);

        let argv = ["ratum-prime"];
        let file = Options { payout_script: Some("51".into()), ..Options::default() };
        let merged = Options::parse_from(argv).over(file, argv);
        assert_eq!(merged.payout_script.as_deref(), Some("51"));
    }

    #[test]
    fn the_command_line_and_the_file_share_one_field_list() {
        let c = Options::parse_from(["ratum-prime", "--min-diff", "16384", "--dump-ledger"]);
        assert_eq!(c.min_diff, Some(16384));
        assert!(c.dump_ledger);
        assert_eq!(
            parse_toml("min-diff = 16384\n").unwrap(),
            Options { dump_ledger: false, ..c },
            "the same setting reads the same from either source"
        );
    }
}
