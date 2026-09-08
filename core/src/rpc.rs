use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

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
    #[error("rpc http {0}: {1}")]
    Http(u16, String),
    #[error("rpc error: {0}")]
    Rpc(String),
}

impl Error {
    pub fn is_unauthorized(&self) -> bool {
        matches!(self, Error::Http(401 | 403, _))
    }

    pub fn is_method_not_found(&self) -> bool {
        match self {
            Error::Rpc(m) => m.contains("-32601") || m.contains("Method not found"),
            _ => false,
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
    fn parse(name: &str) -> Chain {
        match name {
            "main" => Chain::Main,
            "test" => Chain::Test,
            "testnet4" => Chain::Testnet4,
            "signet" => Chain::Signet,
            "regtest" => Chain::Regtest,
            _ => Chain::Other,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Chain::Main => "main",
            Chain::Test => "test",
            Chain::Testnet4 => "testnet4",
            Chain::Signet => "signet",
            Chain::Regtest => "regtest",
            Chain::Other => "other",
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
pub struct NextBlock {
    pub coinbase_value: u64,
    pub bits: u32,
}

#[derive(Clone)]
pub struct Client {
    url: String,
    authorization: Arc<Mutex<String>>,
    cookie_path: Option<PathBuf>,
    pub timeout: Duration,
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

impl Client {
    pub fn new(url: &str, user: &str, password: &str) -> Result<Self, Error> {
        Self::build(url, basic_auth(user, password), None)
    }

    pub fn with_cookie(url: &str, cookie_path: PathBuf) -> Result<Self, Error> {
        let (user, password) = read_cookie(&cookie_path)?;
        Self::build(url, basic_auth(&user, &password), Some(cookie_path))
    }

    fn build(
        url: &str,
        authorization: String,
        cookie_path: Option<PathBuf>,
    ) -> Result<Self, Error> {
        let rest = url
            .strip_prefix("http://")
            .or_else(|| url.strip_prefix("https://"))
            .ok_or_else(|| Error::BadUrl(url.to_string()))?;
        let authority = rest.split('/').next().unwrap_or(rest);
        if authority.is_empty() || !authority.contains(':') {
            return Err(Error::BadUrl(url.to_string()));
        }
        Ok(Client {
            url: url.to_string(),
            authorization: Arc::new(Mutex::new(authorization)),
            cookie_path,
            timeout: DEFAULT_TIMEOUT,
        })
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
                    Error::Http(status, json.to_string())
                });
            }
        };
        if !parsed["error"].is_null() {
            return Err(Error::Rpc(parsed["error"].to_string()));
        }
        if status != 200 {
            return Err(Error::Http(status, json.to_string()));
        }
        match parsed.get("result") {
            Some(result) => Ok(result.clone()),
            None => Err(Error::BadResponse("response carries neither result nor error".into())),
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn tip(&self) -> Result<Tip, Error> {
        let info = self.call("getblockchaininfo", serde_json::json!([]))?;
        let display = info["bestblockhash"]
            .as_str()
            .ok_or_else(|| Error::BadResponse("no bestblockhash".into()))?;
        let height =
            info["blocks"].as_u64().ok_or_else(|| Error::BadResponse("no blocks".into()))? as u32;
        let difficulty = info["difficulty"]
            .as_f64()
            .ok_or_else(|| Error::BadResponse("no difficulty".into()))?;
        let chain = Chain::parse(
            info["chain"].as_str().ok_or_else(|| Error::BadResponse("no chain".into()))?,
        );
        let hash: [u8; 32] = hex::decode(display)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| Error::BadResponse(format!("bestblockhash {display:?}")))?;
        Ok(Tip { hash: crate::bitcoin::reversed(&hash), height, difficulty, chain })
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

    pub fn next_block(&self) -> Result<NextBlock, Error> {
        let result =
            self.call("getblocktemplate", serde_json::json!([{"rules": ["segwit", "blake2b"]}]))?;
        let coinbase_value = result["coinbasevalue"]
            .as_u64()
            .ok_or_else(|| Error::BadResponse("no coinbasevalue".into()))?;
        let bits_hex =
            result["bits"].as_str().ok_or_else(|| Error::BadResponse("no bits".into()))?;
        let bits = u32::from_str_radix(bits_hex, 16)
            .map_err(|_| Error::BadResponse(format!("bits {bits_hex:?}")))?;
        Ok(NextBlock { coinbase_value, bits })
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
