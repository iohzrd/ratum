//! The node's JSON-RPC client: the calls both binaries make, the chain and tip the node reports,
//! and the cookie file re-read once when the node refuses the credential, which is what a node
//! restart needs.

use crate::bitcoin::address;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

const HTTP_PORT: u16 = 80;
const HTTPS_PORT: u16 = 443;

const TEMPLATE_RULES: [&str; 2] = ["segwit", "blake2b"];

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cannot parse RPC url {0:?}")]
    BadUrl(String),
    #[error("bad rpc cookie: {0}")]
    BadCookie(String),
    #[error("rpc io: {0}")]
    Io(#[from] std::io::Error),
    #[error("rpc transport: {0}")]
    Transport(#[from] minreq::Error),
    #[error("malformed rpc response: {0}")]
    BadResponse(String),
    #[error("rpc http {status}: {body}")]
    Http { status: u16, body: String },
    #[error("rpc error {code}: {message}")]
    Rpc { code: i64, message: String },
}

const RPC_METHOD_NOT_FOUND: i64 = -32601;
const RPC_INVALID_ADDRESS_OR_KEY: i64 = -5;

impl Error {
    pub fn is_unauthorized(&self) -> bool {
        matches!(self, Self::Http { status: 401 | 403, .. })
    }

    pub fn is_method_not_found(&self) -> bool {
        matches!(self, Self::Rpc { code: RPC_METHOD_NOT_FOUND, .. })
    }

    pub(crate) fn is_not_found(&self) -> bool {
        matches!(self, Self::Rpc { code: RPC_INVALID_ADDRESS_OR_KEY, .. })
    }

    fn from_rpc_object(error: &serde_json::Value) -> Self {
        Self::Rpc {
            code: error["code"].as_i64().unwrap_or(0),
            message: error["message"].as_str().map_or_else(|| error.to_string(), str::to_string),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chain {
    Main,
    Test,
    Testnet4,
    Signet,
    Regtest,
    Other,
}

impl Chain {
    fn parse(name: &str) -> Self {
        match name {
            "main" => Self::Main,
            "test" => Self::Test,
            "testnet4" => Self::Testnet4,
            "signet" => Self::Signet,
            "regtest" => Self::Regtest,
            _ => Self::Other,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Main => "main",
            Self::Test => "test",
            Self::Testnet4 => "testnet4",
            Self::Signet => "signet",
            Self::Regtest => "regtest",
            Self::Other => "other",
        }
    }

    /// The prefixes of this chain's addresses; none for a chain this build has no name for.
    pub fn address_prefixes(self) -> Option<address::Prefixes> {
        match self {
            Self::Main => Some(address::MAIN),
            Self::Test | Self::Testnet4 | Self::Signet => Some(address::TEST),
            Self::Regtest => Some(address::REGTEST),
            Self::Other => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Tip {
    pub hash: [u8; 32],
    pub height: u32,
    pub difficulty: f64,
    pub chain: Chain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TemplateSummary {
    pub coinbase_value: u64,
    pub bits: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MiningInfo {
    pub chain: Chain,
    pub network_hashps: f64,
    pub warnings: Vec<String>,
}

/// Whether a `getblockheader` confirmation count says the block is on the node's best chain.
/// The node answers a negative count for a block on a branch it does not build on, and 0 for
/// the tip itself.
pub const fn on_best_chain(confirmations: i64) -> bool {
    confirmations >= 0
}

/// The field of an RPC result, or `BadResponse` naming the one the node did not answer.
/// Zero is a value like any other: a chain at its genesis block answers 0 blocks.
fn u64_field(v: &serde_json::Value, key: &str) -> Result<u64, Error> {
    v[key].as_u64().ok_or_else(|| missing(key))
}

fn f64_field(v: &serde_json::Value, key: &str) -> Result<f64, Error> {
    v[key].as_f64().ok_or_else(|| missing(key))
}

fn str_field<'a>(v: &'a serde_json::Value, key: &str) -> Result<&'a str, Error> {
    v[key].as_str().ok_or_else(|| missing(key))
}

fn missing(key: &str) -> Error {
    Error::BadResponse(format!("no {key}"))
}

fn warnings_of(v: &serde_json::Value) -> Vec<String> {
    match v {
        serde_json::Value::Array(a) => a
            .iter()
            .filter_map(|w| w.as_str())
            .filter(|w| !w.is_empty())
            .map(str::to_string)
            .collect(),
        serde_json::Value::String(s) if !s.is_empty() => vec![s.clone()],
        _ => Vec::new(),
    }
}

#[derive(Clone)]
pub struct Client {
    url: String,
    authorization: Arc<Mutex<String>>,
    cookie_path: Option<PathBuf>,
    timeout: Duration,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("url", &self.url)
            .field("authorization", &"<redacted>")
            .field("cookie_path", &self.cookie_path)
            .field("timeout", &self.timeout)
            .finish()
    }
}

fn basic_auth(user: &str, password: &str) -> String {
    use base64::Engine as _;
    let credential = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
    format!("Basic {credential}")
}

struct RpcUrl {
    url: String,
    user: String,
    password: String,
}

fn parse_url(url: &str) -> Result<RpcUrl, Error> {
    let bad = || Error::BadUrl(url.to_string());
    let (scheme, rest) = url.split_once("://").ok_or_else(bad)?;
    if scheme != "http" && scheme != "https" {
        return Err(bad());
    }
    let (user, password, host) = match rest.rsplit_once('@') {
        Some((credentials, host)) => {
            let (user, password) = credentials.split_once(':').unwrap_or((credentials, ""));
            (user, password, host)
        }
        None => ("", "", rest),
    };
    let (authority, path) = match host.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (host, String::new()),
    };
    if authority.is_empty() {
        return Err(bad());
    }
    let has_port = authority.rsplit_once(']').map_or(authority, |(_, after)| after).contains(':');
    let port = match (has_port, scheme) {
        (true, _) => String::new(),
        (false, "https") => format!(":{HTTPS_PORT}"),
        (false, _) => format!(":{HTTP_PORT}"),
    };
    Ok(RpcUrl {
        url: format!("{scheme}://{authority}{port}{path}"),
        user: user.to_string(),
        password: password.to_string(),
    })
}

impl Client {
    /// The client for a node configured with any combination of the credential settings,
    /// taken in the order of the more specific instruction: `user` when it is set, since
    /// naming a user is the most specific; the cookie file when one is given; and otherwise
    /// the `user:password@` the URL itself carries. This is the only constructor, so every
    /// caller applies that one rule, rather than one call site reading a URL's credentials
    /// and another discarding them.
    pub fn new(
        url: &str,
        user: &str,
        password: &str,
        cookie_path: Option<PathBuf>,
    ) -> Result<Self, Error> {
        let parsed = parse_url(url)?;
        if let Some(path) = cookie_path.filter(|_| user.is_empty()) {
            let (user, password) = read_cookie(&path)?;
            return Ok(Self::build(parsed.url, basic_auth(&user, &password), Some(path)));
        }
        let (user, password) = if user.is_empty() {
            (parsed.user.as_str(), parsed.password.as_str())
        } else {
            (user, password)
        };
        Ok(Self::build(parsed.url, basic_auth(user, password), None))
    }

    fn build(url: String, authorization: String, cookie_path: Option<PathBuf>) -> Self {
        Self {
            url,
            authorization: Arc::new(Mutex::new(authorization)),
            cookie_path,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    fn refresh_cookie(&self) -> bool {
        let Some(path) = &self.cookie_path else { return false };
        let Ok((user, password)) = read_cookie(path) else { return false };
        let reread = basic_auth(&user, &password);
        let mut held = crate::lock(&self.authorization);
        if *held == reread {
            false
        } else {
            *held = reread;
            true
        }
    }

    pub fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, Error> {
        let body = serde_json::json!({
            "jsonrpc": "1.0",
            "id": "ratum",
            "method": method,
            "params": params,
        })
        .to_string();

        match self.attempt(&body) {
            Err(e) if e.is_unauthorized() && self.refresh_cookie() => self.attempt(&body),
            other => other,
        }
    }

    fn attempt(&self, body: &str) -> Result<serde_json::Value, Error> {
        let authorization = crate::lock(&self.authorization).clone();
        let response = minreq::post(&self.url)
            .with_header("Authorization", authorization)
            .with_header("Content-Type", "application/json")
            .with_body(body)
            .with_timeout(self.timeout.as_secs().max(1))
            .send()?;
        let status = response.status_code as u16;
        let json = String::from_utf8_lossy(response.as_bytes());
        let json = json.trim();

        let parsed: serde_json::Value = match serde_json::from_str(json) {
            Ok(v) => v,
            Err(e) => {
                return Err(if status == 200 {
                    Error::BadResponse(e.to_string())
                } else {
                    Error::Http { status, body: json.to_string() }
                });
            }
        };
        if !parsed["error"].is_null() {
            return Err(Error::from_rpc_object(&parsed["error"]));
        }
        if status != 200 {
            return Err(Error::Http { status, body: json.to_string() });
        }
        parsed
            .get("result")
            .cloned()
            .ok_or_else(|| Error::BadResponse("response carries neither result nor error".into()))
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn tip(&self) -> Result<Tip, Error> {
        let info = self.call("getblockchaininfo", serde_json::json!([]))?;
        let display = str_field(&info, "bestblockhash")?;
        let height = u64_field(&info, "blocks")? as u32;
        let difficulty = f64_field(&info, "difficulty")?;
        let chain = Chain::parse(str_field(&info, "chain")?);
        let hash = crate::bitcoin::hash_from_display_hex(display)
            .ok_or_else(|| Error::BadResponse(format!("bestblockhash {display:?}")))?;
        Ok(Tip { hash, height, difficulty, chain })
    }

    pub fn wait_for_block_height(&self, height: u32, timeout: Duration) -> Result<u32, Error> {
        let ms = (timeout.as_millis() as u64).max(1);
        let mut waiting = self.clone();
        waiting.timeout = timeout.saturating_add(self.timeout);
        let result = waiting.call("waitforblockheight", serde_json::json!([height, ms]))?;
        result["height"]
            .as_u64()
            .map(|h| h as u32)
            .ok_or_else(|| Error::BadResponse("no height in waitforblockheight".into()))
    }

    pub fn block_template(&self) -> Result<serde_json::Value, Error> {
        self.call("getblocktemplate", serde_json::json!([{"rules": TEMPLATE_RULES}]))
    }

    pub fn template_summary(&self) -> Result<TemplateSummary, Error> {
        let result = self.block_template()?;
        let coinbase_value = u64_field(&result, "coinbasevalue")?;
        let bits_hex = str_field(&result, "bits")?;
        let bits = u32::from_str_radix(bits_hex, 16)
            .map_err(|_| Error::BadResponse(format!("bits {bits_hex:?}")))?;
        Ok(TemplateSummary { coinbase_value, bits })
    }

    pub fn mining_info(&self) -> Result<MiningInfo, Error> {
        let v = self.call("getmininginfo", serde_json::json!([]))?;
        let chain = Chain::parse(str_field(&v, "chain")?);
        let network_hashps = f64_field(&v, "networkhashps")?;
        Ok(MiningInfo { chain, network_hashps, warnings: warnings_of(&v["warnings"]) })
    }

    /// The node's confirmation count for the block, or none when it stores no such block.
    /// `on_best_chain` reads the count's sign, which is what says whether the block is still
    /// on the chain the node builds on.
    pub fn block_confirmations(&self, hash_display_hex: &str) -> Result<Option<i64>, Error> {
        let header = match self.call("getblockheader", serde_json::json!([hash_display_hex, true]))
        {
            Ok(h) => h,
            Err(e) if e.is_not_found() => return Ok(None),
            Err(e) => return Err(e),
        };
        header["confirmations"]
            .as_i64()
            .map(Some)
            .ok_or_else(|| Error::BadResponse("no confirmations in getblockheader".into()))
    }

    pub fn submit_block(&self, block: &[u8]) -> Result<Option<String>, Error> {
        let result = self.call("submitblock", serde_json::json!([hex::encode(block)]))?;
        Ok(match result {
            serde_json::Value::Null => None,
            serde_json::Value::String(reason) => Some(reason),
            other => Some(other.to_string()),
        })
    }
}

fn read_cookie(path: &Path) -> Result<(String, String), Error> {
    let text = std::fs::read_to_string(path)?;
    match text.trim().split_once(':') {
        Some((u, p)) => Ok((u.to_string(), p.to_string())),
        None => Err(Error::BadCookie(format!(
            "{} is not a cookie file: expected user:password",
            path.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_auth_encodes_the_credential() {
        assert_eq!(basic_auth("x", "y"), "Basic eDp5");
        assert_eq!(basic_auth("rpcuser", "rpcpass"), "Basic cnBjdXNlcjpycGNwYXNz");
    }

    fn client(url: &str, user: &str, password: &str) -> Result<Client, Error> {
        Client::new(url, user, password, None)
    }

    #[test]
    fn parses_urls() {
        let c = client("http://127.0.0.1:18443", "x", "y").unwrap();
        assert_eq!(c.url, "http://127.0.0.1:18443");
        assert_eq!(*crate::lock(&c.authorization), "Basic eDp5");

        let c = client("http://node.example:8332/wallet/main", "u", "p").unwrap();
        assert_eq!(c.url, "http://node.example:8332/wallet/main");

        let c = client("https://node.example:8332", "u", "p").unwrap();
        assert_eq!(c.url, "https://node.example:8332");

        let c = client("http://nohost", "u", "p").unwrap();
        assert_eq!(c.url, "http://nohost:80", "the scheme's port applies");

        for bad in ["127.0.0.1:18443", "ftp://127.0.0.1:18443", "http://"] {
            assert!(client(bad, "x", "y").is_err(), "{bad:?} should not parse");
        }
    }

    #[test]
    fn recognizes_a_credential_the_node_refuses() {
        assert!(Error::Http { status: 401, body: "Unauthorized".into() }.is_unauthorized());
        assert!(Error::Http { status: 403, body: String::new() }.is_unauthorized());
        for other in [
            Error::Http { status: 500, body: "internal".into() },
            Error::Http { status: 404, body: String::new() },
            rpc_error(-8, "Invalid parameter"),
            Error::BadResponse("no status code".into()),
        ] {
            assert!(!other.is_unauthorized(), "{other} is not a refused credential");
        }
    }

    fn rpc_error(code: i64, message: &str) -> Error {
        Error::from_rpc_object(&serde_json::json!({"code": code, "message": message}))
    }

    #[test]
    fn an_error_object_is_read_into_its_code_and_message() {
        let e = rpc_error(-5, "Block not found");
        assert!(matches!(&e, Error::Rpc { code: -5, message } if message == "Block not found"));
        assert_eq!(e.to_string(), "rpc error -5: Block not found");
        let bare = Error::from_rpc_object(&serde_json::json!("string error"));
        assert!(matches!(&bare, Error::Rpc { code: 0, message } if message == "\"string error\""));
    }

    #[test]
    fn recognizes_a_hash_the_node_stores_no_block_under() {
        assert!(rpc_error(-5, "Block not found").is_not_found());
        for other in [
            rpc_error(-8, "Block height out of range"),
            rpc_error(-32601, "Method not found"),
            rpc_error(-1, "Block not found"),
            Error::Http { status: 404, body: String::new() },
            Error::BadResponse("no confirmations in getblockheader".into()),
        ] {
            assert!(!other.is_not_found(), "{other} is not a missing block: the code decides");
        }
    }

    #[test]
    fn urls_take_both_schemes_and_optional_credentials() {
        assert!(client("http://u:p@127.0.0.1:8332", "", "").is_ok());
        assert!(client("https://u:p@node.example:8332", "", "").is_ok());
        assert!(client("http://127.0.0.1:8332", "", "").is_ok());
        assert!(matches!(client("ftp://127.0.0.1:8332", "", ""), Err(Error::BadUrl(_))));
        assert!(matches!(client("127.0.0.1:8332", "", ""), Err(Error::BadUrl(_))));
        assert_eq!(
            client("http://nohost", "", "").map(|c| c.url).ok(),
            Some("http://nohost:80".to_string()),
            "the scheme's port applies"
        );
        assert!(client("http://", "", "").is_err());
    }

    /// The one rule every caller reaches: a named user first, then a cookie file, then the
    /// credentials the URL carries.
    #[test]
    fn credentials_are_taken_in_order_of_the_more_specific_setting() {
        let authorization = |c: &Client| crate::lock(&c.authorization).clone();
        let url = "http://u:p@127.0.0.1:8332";

        let c = client(url, "", "").unwrap();
        assert_eq!(authorization(&c), basic_auth("u", "p"), "the URL's own credentials");
        assert_eq!(c.url, "http://127.0.0.1:8332", "which are not left in the URL");

        let c = client(url, "flag", "word").unwrap();
        assert_eq!(authorization(&c), basic_auth("flag", "word"), "a named user wins");

        let dir = std::env::temp_dir().join(format!("ratum-cookie-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cookie");
        std::fs::write(&path, "__cookie__:secret\n").unwrap();

        let c = Client::new(url, "", "", Some(path.clone())).unwrap();
        assert_eq!(
            authorization(&c),
            basic_auth("__cookie__", "secret"),
            "the cookie file outranks the URL's credentials"
        );
        assert_eq!(c.cookie_path, Some(path.clone()), "and is re-read on a refused credential");

        let c = Client::new(url, "flag", "word", Some(path)).unwrap();
        assert_eq!(authorization(&c), basic_auth("flag", "word"), "a named user wins over both");
        assert_eq!(c.cookie_path, None, "so there is no cookie to re-read");

        let missing = dir.join("absent");
        assert!(matches!(Client::new(url, "", "", Some(missing)), Err(Error::Io(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_chain_names_the_prefixes_of_its_addresses() {
        assert_eq!(Chain::parse("main").address_prefixes(), Some(address::MAIN));
        for testnet in ["test", "testnet4", "signet"] {
            assert_eq!(Chain::parse(testnet).address_prefixes(), Some(address::TEST), "{testnet}");
        }
        assert_eq!(Chain::parse("regtest").address_prefixes(), Some(address::REGTEST));
        assert_eq!(Chain::parse("blake2btest").address_prefixes(), None);
    }

    #[test]
    fn warnings_read_back_from_either_shape() {
        use serde_json::json;
        assert_eq!(
            warnings_of(&json!(["unknown new rules activated"])),
            ["unknown new rules activated"]
        );
        assert_eq!(
            warnings_of(&json!("a pre-29 node answers one string")),
            ["a pre-29 node answers one string"]
        );
        assert!(warnings_of(&json!([])).is_empty(), "an array with no warning");
        assert!(warnings_of(&json!("")).is_empty(), "the empty string is no warning");
        assert!(warnings_of(&json!(null)).is_empty(), "a node that reports no field");
        assert_eq!(warnings_of(&json!(["", "second"])), ["second"], "empty entries are dropped");
    }

    #[test]
    fn recognizes_a_method_the_node_does_not_serve() {
        assert!(rpc_error(-32601, "Method not found").is_method_not_found());

        for other in [
            rpc_error(-8, "Block height out of range"),
            rpc_error(-5, "Method not found"),
            Error::Http { status: 500, body: "internal".into() },
            Error::BadResponse("no header/body split".into()),
            Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out")),
        ] {
            assert!(!other.is_method_not_found(), "{other} is not a missing method");
        }
    }
}
