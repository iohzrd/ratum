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
    /// Whether the node refused the credential rather than the request.
    ///
    /// bitcoind generates a new cookie on every start and deletes it on shutdown
    /// (`GenerateAuthCookie`, `DeleteAuthCookie`), so a node restarted under a running pool
    /// leaves it holding a password that no longer exists. A configured rpcpassword
    /// does not rotate, and a node with one writes no cookie at all.
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

/// The chain the node reports in `getblockchaininfo`'s `chain` field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chain {
    Main,
    Test,
    Testnet4,
    Signet,
    Regtest,
    /// A `chain` value not listed above.
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

    /// The name as `getblockchaininfo` reports it; `"other"` for an unlisted value.
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

/// The two facts the pool reads from a block template: what the next block may pay, and the
/// target it must meet. Not the template itself, which also carries the transactions, the
/// previous hash, the height and more; only these two are read. The gateway, not the pool,
/// builds templates, so the pool has no use for the rest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NextBlock {
    pub coinbase_value: u64,
    /// The compact target the next block must meet, `nBits` in the block header.
    pub bits: u32,
}

#[derive(Clone)]
pub struct Client {
    url: String,
    /// The `Authorization` header value. Shared across clones so a cookie refresh (below)
    /// propagates to every clone of the client, not only the one that received the 401 or 403.
    authorization: Arc<Mutex<String>>,
    /// The cookie file, if the credential came from one. bitcoind generates a new cookie on
    /// every start, so a node restarted under a running pool leaves the held credential
    /// different from the file's; a 401 or 403 re-reads the file so the pool recovers without
    /// being restarted.
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

    /// A client whose credential is read from a bitcoind cookie file and re-read on a 401 or 403.
    pub fn with_cookie(url: &str, cookie_path: PathBuf) -> Result<Self, Error> {
        let (user, password) = read_cookie(&cookie_path)?;
        Self::build(url, basic_auth(&user, &password), Some(cookie_path))
    }

    fn build(
        url: &str,
        authorization: String,
        cookie_path: Option<PathBuf>,
    ) -> Result<Self, Error> {
        // An `http://` or `https://` URL with a host:port authority; a bare host or another
        // scheme is refused. The node on the same host or a private link is plain HTTP; an
        // extra block-submission node behind TLS is where `https://` is used.
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

    /// Re-read the cookie file and update the shared credential. Returns whether the
    /// credential changed, so the caller retries only when there is a new one to try.
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
            // bitcoind generates a new cookie on every start, so a 401 or 403 may mean only that
            // the file now holds a new credential. Re-read it and retry once before returning the
            // error.
            Err(e) if e.is_unauthorized() && self.refresh_cookie() => self.attempt(&body),
            other => other,
        }
    }

    fn attempt(&self, body: &str) -> Result<serde_json::Value, Error> {
        let authorization = crate::lock(&self.authorization).clone();
        // minreq frames the response by Content-Length and decodes chunked transfer, so the
        // body end is found by the protocol rather than by closing the connection. The timeout
        // is a whole-request bound; the long-poll `waitforblockheight` sets it above the
        // node's wait time (the RPC's own timeout argument). Seconds granularity is immaterial
        // (every timeout here is >= 1s).
        let response = minreq::post(&self.url)
            .with_header("Authorization", authorization)
            .with_header("Content-Type", "application/json")
            .with_body(body.to_string())
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
        // A well-formed JSON-RPC response carries a `result` key (null on a bare success such
        // as submitblock's) whenever `error` is null. Its absence is a malformed response, not
        // a success: without this, `submit_block` would read a `result`-less 200 as a null
        // result and report a block the node never accepted.
        match parsed.get("result") {
            Some(result) => Ok(result.clone()),
            None => Err(Error::BadResponse("response carries neither result nor error".into())),
        }
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
        let mut hash: [u8; 32] = hex::decode(display)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| Error::BadResponse(format!("bestblockhash {display:?}")))?;
        hash.reverse();
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

    /// The value and the compact target of the block the node would build on its tip. The
    /// pool holds `bits` per tip so it can refuse a job that claims an easier network target
    /// than the chain's, which would let a gateway make ordinary shares count as blocks.
    pub fn next_block(&self) -> Result<NextBlock, Error> {
        // The node requires a getblocktemplate client to declare each active fork rule, as
        // it does for segwit: without "blake2b" it refuses with "requires explicit client
        // support" once the BLAKE2b deployment is active.
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
            other => Some(other.as_str().map_or_else(|| other.to_string(), str::to_string)),
        })
    }
}

/// Read a bitcoind cookie file, whose one line is `user:password`.
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

    #[test]
    fn parses_urls() {
        let c = Client::new("http://127.0.0.1:18443", "x", "y").unwrap();
        assert_eq!(c.url, "http://127.0.0.1:18443");
        assert_eq!(*crate::lock(&c.authorization), "Basic eDp5");

        let c = Client::new("http://node.example:8332/wallet/main", "u", "p").unwrap();
        assert_eq!(c.url, "http://node.example:8332/wallet/main");

        let c = Client::new("https://node.example:8332", "u", "p").unwrap();
        assert_eq!(c.url, "https://node.example:8332");

        for bad in ["127.0.0.1:18443", "ftp://127.0.0.1:18443", "http://", "http://nohost"] {
            assert!(Client::new(bad, "x", "y").is_err(), "{bad:?} should not parse");
        }
    }

    /// A refused credential is not a refused request. bitcoind generates a new cookie every
    /// time it starts, so this is the response a node restarted under a running pool gives.
    #[test]
    fn recognizes_a_credential_the_node_refuses() {
        assert!(Error::Http(401, "Unauthorized".into()).is_unauthorized());
        assert!(Error::Http(403, String::new()).is_unauthorized());
        for other in [
            Error::Http(500, "internal".into()),
            Error::Http(404, String::new()),
            Error::Rpc(r#"{"code":-8}"#.to_string()),
            Error::BadResponse("no status code".into()),
        ] {
            assert!(!other.is_unauthorized(), "{other} is not a refused credential");
        }
    }

    #[test]
    fn recognizes_a_method_the_node_does_not_serve() {
        let missing = Error::Rpc(r#"{"code":-32601,"message":"Method not found"}"#.to_string());
        assert!(missing.is_method_not_found());

        for other in [
            Error::Rpc(r#"{"code":-8,"message":"Block height out of range"}"#.to_string()),
            Error::Http(500, "internal".into()),
            Error::BadResponse("no header/body split".into()),
            Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out")),
        ] {
            assert!(!other.is_method_not_found(), "{other} is not a missing method");
        }
    }
}
