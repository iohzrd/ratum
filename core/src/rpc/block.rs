//! One block as the node prints it: `getblock` at verbosity 1, and its coinbase from verbose
//! `getrawtransaction`, which needs no txindex when the block hash is given.

use super::{
    Client, Error, f64_field, i64_field, missing, node_difficulty, string_field, u32_field,
    u64_field,
};
use crate::bitcoin::{HASH_SIZE, display_hex_bytes};

/// A block as `getblock` at verbosity 1 prints it: the header fields the node reports and
/// the coinbase's txid, the first of `tx`. The hashes are display hex.
#[derive(Clone, Debug, PartialEq)]
pub struct Block {
    pub hash: String,
    pub height: u32,
    pub time: u64,
    pub mediantime: u64,
    pub confirmations: i64,
    pub version: i64,
    pub bits: String,
    pub difficulty: f64,
    pub nonce: u64,
    pub merkle_root: String,
    /// None on the genesis block.
    pub previous_hash: Option<String>,
    /// None at the tip.
    pub next_hash: Option<String>,
    pub size: u64,
    pub weight: u64,
    pub tx_count: u64,
    pub coinbase_txid: String,
}

impl Block {
    pub fn decode(v: &serde_json::Value) -> Result<Self, Error> {
        let coinbase_txid = v["tx"]
            .as_array()
            .ok_or_else(|| missing("tx"))?
            .first()
            .and_then(|t| t.as_str())
            .ok_or_else(|| missing("txid in tx"))?
            .to_string();
        Ok(Self {
            hash: string_field(v, "hash")?,
            height: u32_field(v, "height")?,
            time: u64_field(v, "time")?,
            mediantime: u64_field(v, "mediantime")?,
            confirmations: i64_field(v, "confirmations")?,
            version: i64_field(v, "version")?,
            bits: string_field(v, "bits")?,
            difficulty: node_difficulty(v)?,
            nonce: u64_field(v, "nonce")?,
            merkle_root: string_field(v, "merkleroot")?,
            previous_hash: v["previousblockhash"].as_str().map(str::to_string),
            next_hash: v["nextblockhash"].as_str().map(str::to_string),
            size: u64_field(v, "size")?,
            weight: u64_field(v, "weight")?,
            tx_count: u64_field(v, "nTx")?,
            coinbase_txid,
        })
    }
}

/// A coinbase as verbose `getrawtransaction` prints it: its txid, its input's script, and
/// its outputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coinbase {
    pub txid: String,
    /// The coinbase input's script, hex.
    pub script_sig: String,
    pub outputs: Vec<Output>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub sats: u64,
    /// None for an OP_RETURN or a non-standard script.
    pub address: Option<String>,
    /// The scriptPubKey, hex.
    pub script: String,
}

impl Coinbase {
    pub fn decode(v: &serde_json::Value) -> Result<Self, Error> {
        let outputs = v["vout"]
            .as_array()
            .ok_or_else(|| missing("vout"))?
            .iter()
            .map(|out| {
                Ok(Output {
                    sats: crate::btc_to_sats(f64_field(out, "value")?),
                    address: out["scriptPubKey"]["address"].as_str().map(str::to_string),
                    script: string_field(&out["scriptPubKey"], "hex")?,
                })
            })
            .collect::<Result<_, Error>>()?;
        Ok(Self {
            txid: string_field(v, "txid")?,
            script_sig: string_field(&v["vin"][0], "coinbase")?,
            outputs,
        })
    }

    /// The sum of the outputs, sats.
    pub fn value(&self) -> u64 {
        self.outputs.iter().map(|o| o.sats).sum()
    }
}

impl Client {
    /// The hash of the block at `height` in display order, the order the node prints it in,
    /// or none when the height is above the node's tip.
    pub fn block_hash(&self, height: u32) -> Result<Option<[u8; HASH_SIZE]>, Error> {
        match self.call("getblockhash", serde_json::json!([height])) {
            Ok(v) => v
                .as_str()
                .and_then(display_hex_bytes)
                .map(Some)
                .ok_or_else(|| Error::BadResponse(format!("{v} is not a hash"))),
            Err(e) if e.is_invalid_parameter() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `getblock` at verbosity 1 for the block at `hash_display_hex`, or none when the node
    /// stores no block under it.
    pub fn block(&self, hash_display_hex: &str) -> Result<Option<Block>, Error> {
        match self.call("getblock", serde_json::json!([hash_display_hex, 1])) {
            Ok(v) => Block::decode(&v).map(Some),
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `block`'s coinbase: verbose `getrawtransaction` with the block hash, which needs no
    /// txindex.
    pub fn coinbase(&self, block: &Block) -> Result<Coinbase, Error> {
        let params = serde_json::json!([block.coinbase_txid, true, block.hash]);
        Coinbase::decode(&self.call("getrawtransaction", params)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{
        FakeNode, HASH, PREVIOUS, TXID, node_block, node_block_header_v2, node_coinbase,
    };

    fn client(url: &str) -> Client {
        Client::new(url, "u", "p", None).unwrap()
    }

    #[test]
    fn a_block_read_answers_none_for_what_the_node_does_not_hold() {
        let node = FakeNode::start(move |method, params| match method {
            "getblockhash" if params[0] == 7 => Ok(serde_json::json!(HASH)),
            "getblockhash" if params[0] == 8 => Ok(serde_json::json!(7)),
            "getblockhash" if params[0] == 10 => Ok(serde_json::json!("zz")),
            "getblockhash" => Err((-8, "Block height out of range")),
            "getblock" if params == &serde_json::json!([HASH, 1]) => Ok(node_block()),
            "getblock" => Err((-5, "Block not found")),
            "getrawtransaction" if params == &serde_json::json!([TXID, true, HASH]) => {
                Ok(node_coinbase(["a", "b"]))
            }
            "getrawtransaction" => Err((-5, "No such transaction found in the provided block")),
            _ => Err((-32601, "Method not found")),
        });
        let c = client(&node.url());
        assert_eq!(c.block_hash(7).unwrap(), display_hex_bytes(HASH));
        assert_eq!(c.block_hash(9).unwrap(), None);
        assert_eq!(
            c.block_hash(8).unwrap_err().to_string(),
            "malformed rpc response: 7 is not a hash"
        );
        assert_eq!(
            c.block_hash(10).unwrap_err().to_string(),
            "malformed rpc response: \"zz\" is not a hash"
        );

        let block = c.block(HASH).unwrap().unwrap();
        assert_eq!(block, Block::decode(&node_block()).unwrap());
        assert_eq!(block.hash, HASH);
        assert_eq!(block.coinbase_txid, TXID);
        assert_eq!(block.previous_hash.as_deref(), Some(PREVIOUS));
        assert_eq!(c.block(&"00".repeat(32)).unwrap(), None);

        let coinbase = c.coinbase(&block).unwrap();
        assert_eq!(coinbase.txid, TXID);
        assert_eq!(coinbase.script_sig, "03fed80e");
        assert_eq!(coinbase.value(), 312_500_000);
        assert_eq!(
            coinbase.outputs,
            [
                Output { sats: 300_000_000, address: Some("a".into()), script: "0014aa".into() },
                Output { sats: 12_500_000, address: Some("b".into()), script: "0014bb".into() },
                Output { sats: 0, address: None, script: "6a24aa21a9ed".into() },
            ]
        );
        let other = Block { hash: "00".repeat(32), ..block };
        let e = c.coinbase(&other).unwrap_err();
        assert!(e.is_not_found(), "a missing transaction is an error, not a missing block: {e}");
    }

    #[test]
    fn a_block_and_a_coinbase_decode_or_name_the_field_the_node_did_not_answer() {
        let mut genesis = node_block();
        genesis.as_object_mut().unwrap().remove("previousblockhash");
        assert_eq!(Block::decode(&genesis).unwrap().previous_hash, None);
        let mut tip = node_block();
        tip.as_object_mut().unwrap().remove("nextblockhash");
        tip["confirmations"] = serde_json::json!(-1);
        let tip = Block::decode(&tip).unwrap();
        assert_eq!(tip.next_hash, None);
        assert_eq!(tip.confirmations, -1, "the node's count, sign included");
        assert_eq!(Block::decode(&node_block()).unwrap().difficulty, 1234.5, "the field verbatim");
        let v2 = Block::decode(&node_block_header_v2()).unwrap();
        let from_bits = crate::target::node_difficulty_from_bits(0x1702c4e4).unwrap();
        assert_eq!(v2.difficulty, from_bits, "29.4.2 omits difficulty on a header-v2 block");
        assert_eq!(v2.bits, "1702c4e4");
        let mut no_difficulty = node_block_header_v2();
        no_difficulty["bits"] = serde_json::json!("1d80ffff");
        no_difficulty.as_object_mut().unwrap().remove("difficulty_blake2b");
        assert_eq!(
            Block::decode(&no_difficulty).unwrap_err().to_string(),
            "malformed rpc response: no difficulty, bits or difficulty_blake2b"
        );
        let mut short = node_block();
        short.as_object_mut().unwrap().remove("merkleroot");
        assert_eq!(
            Block::decode(&short).unwrap_err().to_string(),
            "malformed rpc response: no merkleroot"
        );
        for tx in [serde_json::json!([]), serde_json::json!([1])] {
            let mut no_coinbase = node_block();
            no_coinbase["tx"] = tx;
            assert_eq!(
                Block::decode(&no_coinbase).unwrap_err().to_string(),
                "malformed rpc response: no txid in tx"
            );
        }
        let mut tall = node_block();
        tall["height"] = serde_json::json!(1u64 << 32);
        assert_eq!(
            Block::decode(&tall).unwrap_err().to_string(),
            "malformed rpc response: height 4294967296 above u32"
        );

        let mut dust = node_coinbase(["a", "b"]);
        dust["vout"][1]["value"] = serde_json::json!(0.00000546);
        assert_eq!(Coinbase::decode(&dust).unwrap().outputs[1].sats, 546, "rounded to sats");
        assert_eq!(
            Coinbase::decode(&serde_json::json!({})).unwrap_err().to_string(),
            "malformed rpc response: no vout"
        );
        let mut no_script = node_coinbase(["a", "b"]);
        no_script["vin"] = serde_json::json!([{ "txid": "00", "vout": 0 }]);
        assert_eq!(
            Coinbase::decode(&no_script).unwrap_err().to_string(),
            "malformed rpc response: no coinbase",
            "an input that spends an output is not a coinbase's"
        );
    }
}
