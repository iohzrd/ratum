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
