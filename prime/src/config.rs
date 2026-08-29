//! The pool's configuration file: settings whose names are the command line's without their
//! leading dashes, so there is one vocabulary rather than two.
//!
//! ```toml
//! # the node this pool watches and relays to
//! rpc = "http://127.0.0.1:8332"
//! rpc-user = "ratum"
//!
//! # the smallest share difficulty credited, a power of two
//! min-diff = 16384
//! motd = "RATUM Prime"
//! ```
//!
//! TOML because this is a Rust program, and because settings that determine where money goes
//! need comments beside them.
//!
//! The settings are typed, so a `min-diff` of `"soon"` is refused at the line it is on
//! rather than several steps later, and an unknown name is refused with the list of known
//! ones. The command line is parsed separately (by clap); a setting given in both places
//! takes the command line's value, and `main` applies each default and validates each meaning.

/// Declares the file's settings once. Each field is optional so its absence in the file is
/// distinguishable from its default, which lets the command line override it. The kebab-case
/// names match the command-line flags, so there is one vocabulary rather than two.
macro_rules! settings {
    ($($(#[$doc:meta])* $name:ident : $ty:ty),* $(,)?) => {
        #[derive(Debug, Default, PartialEq, serde::Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "kebab-case")]
        pub struct Config {
            $($(#[$doc])* pub $name: Option<$ty>,)*
        }

        impl Config {
            /// Whether the file holds a secret, and so whether its permissions matter.
            pub fn holds_a_secret(&self) -> bool {
                self.rpc_pass.is_some()
            }

            /// The command-line flag each setting stands for, `--kebab-name`. The clap parser
            /// must accept every one, or a setting written in a file has no way to be given on
            /// the command line; the `pool_cli` test `every_file_setting_is_a_clap_flag` walks
            /// this list and checks that.
            pub fn flags() -> Vec<String> {
                vec![$(format!("--{}", stringify!($name).replace('_', "-")),)*]
            }
        }
    };
}

// `config` is deliberately absent: a configuration file cannot name another one, and
// `deny_unknown_fields` is what rejects it.
settings! {
    listen: String,
    stats_listen: String,
    advertise_address: String,
    data_dir: String,
    key: String,
    motd: String,
    min_diff: u64,
    max_connections: usize,
    payout_address: String,
    payout_script: String,
    coinbase_tag: String,
    prime_id: u32,
    ledger: String,
    ledger_keep: usize,
    window: f64,
    window_floor: u128,
    min_payout: u64,
    fee_bps: u16,
    activation_height: u32,
    headline: String,
    rpc: String,
    rpc_user: String,
    rpc_pass: String,
    rpc_cookie: String,
    poll: f64,
}

pub fn parse(text: &str) -> Result<Config, toml::de::Error> {
    toml::from_str(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_parse_into_their_typed_fields() {
        let c = parse("rpc-user = \"ratum\"\nmin-diff = 16384\nwindow = 8.5\n").unwrap();
        assert_eq!(c.min_diff, Some(16384));
        assert_eq!(c.window, Some(8.5));
        assert_eq!(c.rpc_user, Some("ratum".to_string()));
        assert_eq!(c.listen, None, "a setting not written stays unset");
    }

    #[test]
    fn nothing_written_is_nothing_set() {
        assert_eq!(parse("").unwrap(), Config::default());
        assert_eq!(parse("# only a comment\n").unwrap(), Config::default());
    }

    /// The reason for TOML: a file an operator edits once can carry comments.
    #[test]
    fn a_setting_may_be_annotated() {
        let c =
            parse("# the smallest share difficulty credited\nmin-diff = 16384  # a power of two\n")
                .unwrap();
        assert_eq!(c.min_diff, Some(16384));
    }

    /// The point of typing them: caught here rather than several steps later, with the bad
    /// value and its line.
    #[test]
    fn a_value_of_the_wrong_type_is_refused_where_it_is() {
        let e = parse("motd = \"fine\"\nmin-diff = \"soon\"\n").unwrap_err().to_string();
        assert!(e.contains("min-diff"), "{e}");
        assert!(e.contains("line 2"), "{e}");
    }

    /// A name the pool does not have is caught here rather than several steps later, and
    /// the ones it does have are listed.
    #[test]
    fn a_name_the_pool_does_not_have_is_refused() {
        let e = parse("min-dif = 1\n").unwrap_err().to_string();
        assert!(e.contains("min-dif"), "{e}");
        assert!(e.contains("min-diff"), "the ones it does have are named: {e}");
    }

    /// A configuration file cannot name another one, and the same check rejects it.
    #[test]
    fn a_configuration_file_cannot_name_another_one() {
        let e = parse("config = \"/etc/other.toml\"\n").unwrap_err().to_string();
        assert!(e.contains("config"), "{e}");
    }

    #[test]
    fn text_that_is_not_settings_is_an_error() {
        for text in ["oops\n", "min-diff = \n", "[section]\nmin-diff = 1\n"] {
            let e = parse(text).expect_err("not settings").to_string();
            assert!(!e.is_empty(), "{text:?}");
        }
    }

    #[test]
    fn only_a_password_makes_the_files_permissions_matter() {
        assert!(!parse("rpc-user = \"ratum\"\n").unwrap().holds_a_secret());
        assert!(parse("rpc-pass = \"hunter2\"\n").unwrap().holds_a_secret());
    }
}
