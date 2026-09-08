macro_rules! settings {
    ($($(#[$doc:meta])* $name:ident : $ty:ty),* $(,)?) => {
        #[derive(Debug, Default, PartialEq, serde::Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "kebab-case")]
        pub struct Config {
            $($(#[$doc])* pub $name: Option<$ty>,)*
        }

        impl Config {
            pub fn holds_a_secret(&self) -> bool {
                self.rpc_pass.is_some()
            }

            pub fn flags() -> Vec<String> {
                vec![$(format!("--{}", stringify!($name).replace('_', "-")),)*]
            }
        }
    };
}

settings! {
    listen: String,
    stats_listen: String,
    advertise_address: String,
    public_gateway: String,
    data_dir: String,
    key: String,
    motd: String,
    allow_agent: String,
    require_split: bool,
    require_v3: bool,
    abw_reveal_after: u64,
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
    rpc: String,
    rpc_user: String,
    rpc_pass: String,
    rpc_cookie: String,
    poll: f64,
}

pub fn parse(text: &str) -> Result<Config, toml::de::Error> {
    toml::from_str(text)
}
