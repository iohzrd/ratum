//! A stand-in bitcoin node: the JSON-RPC a test specifies, served over HTTP.

use super::*;
use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// What the stand-in node reports and stores.
pub struct NodeState {
    pub height: u32,
    pub tip_display: String,
    pub difficulty: f64,
    pub coinbase_value: Option<u64>,
    /// The compact bits the node reports in its template. The pool checks whether a share is
    /// a block against this target, not against a job's self-declared bits.
    pub next_bits: String,
    pub invalid_addresses: HashSet<String>,
    /// Addresses `validateaddress` answers with a 42-byte scriptPubKey, what the node
    /// returns for a future witness version: valid, but over the coinbase output limit.
    pub oversized_addresses: HashSet<String>,
    pub submitted: Vec<String>,
    pub submit_reply: Option<String>,
    pub serves_waitforblockheight: bool,
    pub calls: Vec<String>,
}

impl NodeState {
    fn new() -> Self {
        NodeState {
            height: 100,
            tip_display: "00".repeat(31) + "01",
            difficulty: 1.0,
            coinbase_value: Some(312_500_000),
            next_bits: "207fffff".to_string(),
            invalid_addresses: HashSet::new(),
            oversized_addresses: HashSet::new(),
            submitted: Vec::new(),
            submit_reply: None,
            serves_waitforblockheight: true,
            calls: Vec::new(),
        }
    }
}

/// A JSON-RPC server that serves the calls `ratum::rpc::Client` makes.
pub struct FakeNode {
    addr: SocketAddr,
    pub state: Arc<Mutex<NodeState>>,
    stop: Arc<AtomicUsize>,
}

impl FakeNode {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake node");
        let addr = listener.local_addr().expect("fake node address");
        let state = Arc::new(Mutex::new(NodeState::new()));
        let stop = Arc::new(AtomicUsize::new(0));

        let (s, st) = (Arc::clone(&state), Arc::clone(&stop));
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                if st.load(Ordering::Relaxed) != 0 {
                    return;
                }
                let Ok(conn) = conn else { continue };
                let s = Arc::clone(&s);
                std::thread::spawn(move || {
                    let _ = serve(conn, &s);
                });
            }
        });

        FakeNode { addr, state, stop }
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn set_tip(&self, display_hex: &str, height: u32) {
        let mut s = lock(&self.state);
        s.tip_display = display_hex.to_string();
        s.height = height;
    }

    pub fn set_difficulty(&self, difficulty: f64) {
        lock(&self.state).difficulty = difficulty;
    }

    /// Set the compact bits the node's template reports: the network target the pool checks
    /// blocks against.
    pub fn set_next_bits(&self, bits: &str) {
        lock(&self.state).next_bits = bits.to_string();
    }

    /// Set the coinbase value the template reports. `None` makes getblocktemplate return
    /// an error, the way a node out of sync with its peers does, so the pool reads no template.
    pub fn set_coinbase_value(&self, value: Option<u64>) {
        lock(&self.state).coinbase_value = value;
    }

    pub fn tip_internal(&self) -> [u8; 32] {
        let mut h: [u8; 32] =
            hex::decode(&lock(&self.state).tip_display).unwrap().try_into().unwrap();
        h.reverse();
        h
    }

    pub fn submitted(&self) -> Vec<String> {
        lock(&self.state).submitted.clone()
    }

    pub fn called(&self, method: &str) -> usize {
        lock(&self.state).calls.iter().filter(|m| *m == method).count()
    }

    pub fn wait_for_submission(&self, timeout: Duration) -> Option<String> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(first) = lock(&self.state).submitted.first() {
                return Some(first.clone());
            }
            std::thread::sleep(POLL);
        }
        None
    }
}

impl Drop for FakeNode {
    fn drop(&mut self) {
        self.stop.store(1, Ordering::Relaxed);
        let _ = TcpStream::connect(self.addr);
    }
}

/// The script a stand-in node reports for an address: a P2WPKH-shaped 22 bytes derived
/// from the address itself, so a test can predict it without a wallet.
pub fn script_for_address(address: &str) -> Vec<u8> {
    let mut script = vec![0x00, 0x14];
    let bytes = address.as_bytes();
    for i in 0..20 {
        script.push(bytes.get(i % bytes.len().max(1)).copied().unwrap_or(0) ^ (i as u8));
    }
    script
}

fn serve(mut conn: TcpStream, state: &Arc<Mutex<NodeState>>) -> std::io::Result<()> {
    conn.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new(conn.try_clone()?);

    let mut head = String::new();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        head.push_str(&line);
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body)?;

    let request: serde_json::Value =
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    let method = request["method"].as_str().unwrap_or("").to_string();
    let params = request["params"].clone();
    lock(state).calls.push(method.clone());

    let (result, error) = respond(&method, &params, state);
    let payload =
        serde_json::json!({"result": result, "error": error, "id": request["id"]}).to_string();
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        payload.len(),
        payload
    );
    conn.write_all(response.as_bytes())?;
    conn.flush()
}

fn respond(
    method: &str,
    params: &serde_json::Value,
    state: &Arc<Mutex<NodeState>>,
) -> (serde_json::Value, serde_json::Value) {
    match method {
        "getblockchaininfo" => {
            let s = lock(state);
            (
                serde_json::json!({
                    "chain": "regtest",
                    "bestblockhash": s.tip_display,
                    "blocks": s.height,
                    "difficulty": s.difficulty,
                }),
                serde_json::Value::Null,
            )
        }
        "waitforblockheight" => {
            let serves = lock(state).serves_waitforblockheight;
            if !serves {
                return (
                    serde_json::Value::Null,
                    serde_json::json!({"code": -32601, "message": "Method not found"}),
                );
            }
            // Hold the call briefly, the way a node holds it until the next block, so the
            // watcher thread does not re-issue the call without delay.
            std::thread::sleep(Duration::from_millis(200));
            let s = lock(state);
            (
                serde_json::json!({"height": s.height, "hash": s.tip_display}),
                serde_json::Value::Null,
            )
        }
        "getblocktemplate" => {
            let s = lock(state);
            match s.coinbase_value {
                // Regtest's powLimit bits by default, the easiest target. The work fixtures build
                // jobs at this same nbits, so a conforming job is never easier than the node's next
                // block.
                Some(v) => (
                    serde_json::json!({"coinbasevalue": v, "bits": s.next_bits}),
                    serde_json::Value::Null,
                ),
                None => (
                    serde_json::Value::Null,
                    serde_json::json!({"code": -10, "message": "out of sync"}),
                ),
            }
        }
        "validateaddress" => {
            let address = params[0].as_str().unwrap_or("").to_string();
            if lock(state).invalid_addresses.contains(&address) {
                return (serde_json::json!({"isvalid": false}), serde_json::Value::Null);
            }
            let script = if lock(state).oversized_addresses.contains(&address) {
                // OP_2 followed by a 40-byte witness program: 42 bytes.
                let mut s = vec![0x52, 0x28];
                s.extend(std::iter::repeat_n(0xab, 40));
                s
            } else {
                script_for_address(&address)
            };
            (
                serde_json::json!({
                    "isvalid": true,
                    "scriptPubKey": hex::encode(script),
                }),
                serde_json::Value::Null,
            )
        }
        "submitblock" => {
            let block = params[0].as_str().unwrap_or("").to_string();
            let mut s = lock(state);
            s.submitted.push(block);
            match &s.submit_reply {
                Some(r) => (serde_json::Value::String(r.clone()), serde_json::Value::Null),
                None => (serde_json::Value::Null, serde_json::Value::Null),
            }
        }
        _ => (
            serde_json::Value::Null,
            serde_json::json!({"code": -32601, "message": "Method not found"}),
        ),
    }
}
