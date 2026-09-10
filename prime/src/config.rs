#[derive(Debug, Default, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Config {
    pub listen: Option<String>,
    pub stats_listen: Option<String>,
    pub advertise_address: Option<String>,
    pub public_gateway: Option<String>,
    pub data_dir: Option<String>,
    pub key: Option<String>,
    pub motd: Option<String>,
    pub allow_agent: Option<String>,
    pub require_split: Option<bool>,
    pub require_v3: Option<bool>,
    pub abw_reveal_after: Option<u64>,
    pub min_diff: Option<u64>,
    pub max_connections: Option<usize>,
    pub payout_address: Option<String>,
    pub payout_script: Option<String>,
    pub coinbase_tag: Option<String>,
    pub prime_id: Option<u32>,
    pub ledger: Option<String>,
    pub ledger_keep: Option<usize>,
    pub window: Option<f64>,
    pub window_floor: Option<u128>,
    pub min_payout: Option<u64>,
    pub fee_bps: Option<u16>,
    pub rpc: Option<String>,
    pub rpc_user: Option<String>,
    pub rpc_pass: Option<String>,
    pub rpc_cookie: Option<String>,
    pub poll: Option<f64>,
}

impl Config {
    pub fn holds_a_secret(&self) -> bool {
        self.rpc_pass.is_some()
    }
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

    #[test]
    fn a_setting_may_be_annotated() {
        let c =
            parse("# the smallest share difficulty credited\nmin-diff = 16384  # a power of two\n")
                .unwrap();
        assert_eq!(c.min_diff, Some(16384));
    }

    #[test]
    fn a_value_of_the_wrong_type_is_refused_where_it_is() {
        let e = parse("motd = \"fine\"\nmin-diff = \"soon\"\n").unwrap_err().to_string();
        assert!(e.contains("min-diff"), "{e}");
        assert!(e.contains("line 2"), "{e}");
    }

    #[test]
    fn a_name_the_pool_does_not_have_is_refused() {
        let e = parse("min-dif = 1\n").unwrap_err().to_string();
        assert!(e.contains("min-dif"), "{e}");
        assert!(e.contains("min-diff"), "the ones it does have are named: {e}");
    }

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
