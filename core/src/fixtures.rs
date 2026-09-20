//! Test values both binaries' tests build on: hashes, output scripts, a coinbase assembled the
//! way the gateway assembles one, a fake node, and a block and a coinbase as the node prints
//! them. Compiled under `cfg(test)` and behind the `test-support` feature.

use crate::bitcoin::transaction::TxOut;
use crate::datum::coinbase::{
    BlockLimits, BuiltCoinbase, CoinbaseSpec, ScriptSigInputs, build, script_sig,
};
use serde_json::{Value, json};
use std::io::Write as _;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

pub fn hash(n: u64) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&n.to_be_bytes());
    h
}

pub fn ramp(start: u8) -> [u8; 32] {
    std::array::from_fn(|i| start.wrapping_add(i as u8))
}

pub fn p2wpkh(b: u8) -> Vec<u8> {
    let mut s = vec![0x00, 0x14];
    s.extend_from_slice(&[b; 20]);
    s
}

pub fn p2pkh(b: u8) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 0x14];
    s.extend_from_slice(&[b; 20]);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

pub struct ScriptSigTags<'a> {
    pub tag_primary: &'a str,
    pub tag_secondary: &'a str,
    pub prime_id: u32,
}

const HEIGHT: u32 = 2_544_140;
const UNIQUE_ID: u16 = 0x1234;
const ENPREFIX: u16 = 0xabcd;
const WITNESS_COMMITMENT_HEADER: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

/// A coinbase built the way the gateway builds one, with every output included and a
/// zero witness commitment.
pub fn coinbase(
    tagging: &ScriptSigTags<'_>,
    payout_script: &[u8],
    outputs: &[TxOut],
    coinbase_value: u64,
) -> BuiltCoinbase {
    let (script, target_byte_index_in_script) = script_sig(&ScriptSigInputs {
        height: HEIGHT,
        tag_primary: tagging.tag_primary,
        tag_secondary: tagging.tag_secondary,
        unique_id: UNIQUE_ID,
        prime_id: u64::from(tagging.prime_id),
        wide_prime: false,
        datum_active: true,
    })
    .expect("the fixture tags fit");
    let mut commitment = WITNESS_COMMITMENT_HEADER.to_vec();
    commitment.extend_from_slice(&[0x00; 32]);
    let (built, _) = build(&CoinbaseSpec {
        coinbase_id: 0,
        script_sig: &script,
        target_byte_index_in_script,
        enprefix: ENPREFIX,
        witness_commitment: Some(&commitment),
        pool_payout_script: payout_script,
        coinbase_value,
        outputs,
        limits: BlockLimits::UNLIMITED,
        sigop_budget: u64::MAX,
    });
    built
}

pub const HASH: &str = "00000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub const PREVIOUS: &str = "00000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
pub const NEXT: &str = "00000000000000000000cccccccccccccccccccccccccccccccccccccccccccc";
pub const TXID: &str = "abababababababababababababababababababababababababababababababab";

/// `HASH` at height 973054 as `getblock` at verbosity 1 prints it, holding `TXID` and one
/// more transaction.
pub fn node_block() -> Value {
    json!({
        "hash": HASH,
        "confirmations": 12,
        "height": 973_054,
        "version": 536_870_912,
        "versionHex": "20000000",
        "merkleroot": "e5".repeat(32),
        "time": 1_789_848_656,
        "mediantime": 1_789_848_000,
        "nonce": 123_456_789u64,
        "bits": "1702c4e4",
        "target": "0".repeat(64),
        "difficulty": 1234.5,
        "chainwork": "0".repeat(64),
        "nTx": 233,
        "previousblockhash": PREVIOUS,
        "nextblockhash": NEXT,
        "strippedsize": 70_000,
        "size": 72_907,
        "weight": 190_150,
        "tx": [TXID, "cc".repeat(32)],
    })
}

/// `TXID` as verbose `getrawtransaction` prints it: a coinbase paying `pays` 3 BTC and
/// 0.125 BTC, then a witness commitment.
pub fn node_coinbase(pays: [&str; 2]) -> Value {
    json!({
        "txid": TXID,
        "hash": "dd".repeat(32),
        "version": 1,
        "vin": [{ "coinbase": "03fed80e", "txinwitness": ["00".repeat(32)], "sequence": 0 }],
        "vout": [
            { "value": 3.0, "n": 0, "scriptPubKey": { "hex": "0014aa", "address": pays[0], "type": "witness_v0_keyhash" } },
            { "value": 0.125, "n": 1, "scriptPubKey": { "hex": "0014bb", "address": pays[1], "type": "witness_v0_keyhash" } },
            { "value": 0.0, "n": 2, "scriptPubKey": { "hex": "6a24aa21a9ed", "type": "nulldata" } },
        ],
        "blockhash": HASH,
    })
}

/// A node on a loopback port answering JSON-RPC with `answer` (method and params to the result,
/// or an RPC error's code and message, sent with the status the node sends: 404 for a method
/// it has not, else 500), recording each call's method. A panic in `answer` (a failed
/// assertion on the params) is answered as RPC error -1 carrying its message and raised again
/// on the test thread when the node is dropped. Stopped and joined on drop.
pub struct FakeNode {
    addr: SocketAddr,
    calls: Arc<Mutex<Vec<String>>>,
    failure: Arc<Mutex<Option<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

/// A panic payload's text, as `panic!` and the assertion macros set it.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_else(|| "panic".into())
}

impl FakeNode {
    pub fn start(
        answer: impl Fn(&str, &Value) -> Result<Value, (i64, &'static str)> + Send + 'static,
    ) -> Self {
        const MAX_BODY: usize = 1 << 16;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&calls);
        let failure = Arc::new(Mutex::new(None));
        let failed = Arc::clone(&failure);
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if stopping.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(mut stream) = stream else { break };
                let Ok(peer) = stream.peer_addr() else { continue };
                let Ok(request) = crate::http::read_request(&mut stream, peer, MAX_BODY) else {
                    continue;
                };
                let request: Value = serde_json::from_slice(&request.body).unwrap_or_default();
                let method = request["method"].as_str().unwrap_or_default().to_string();
                crate::lock(&seen).push(method.clone());
                let answered = std::panic::catch_unwind(AssertUnwindSafe(|| {
                    answer(&method, &request["params"])
                }));
                let answered: Result<Value, (i64, String)> = match answered {
                    Ok(Ok(result)) => Ok(result),
                    Ok(Err((code, message))) => Err((code, message.to_string())),
                    Err(payload) => {
                        let message = panic_message(payload.as_ref());
                        crate::lock(&failed).get_or_insert(message.clone());
                        Err((-1, message))
                    }
                };
                let reply = match answered {
                    Ok(result) => crate::http::json(json!({
                        "result": result,
                        "error": null,
                        "id": request["id"],
                    })),
                    Err((code, message)) => crate::http::json(json!({
                        "result": null,
                        "error": {"code": code, "message": message},
                        "id": request["id"],
                    }))
                    .with_status_code(if code == -32601 { 404 } else { 500 }),
                };
                let _ = stream.write_all(&reply.encode(false));
            }
        });
        Self { addr, calls, failure, stop, thread: Some(thread) }
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The methods called so far, in order.
    pub fn calls(&self) -> Vec<String> {
        crate::lock(&self.calls).clone()
    }
}

impl Drop for FakeNode {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // One connection, so the accept loop observes the flag.
        let _ = TcpStream::connect(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        if let Some(message) = crate::lock(&self.failure).take()
            && !std::thread::panicking()
        {
            panic!("the fake node's answer panicked: {message}");
        }
    }
}
