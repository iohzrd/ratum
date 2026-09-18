//! The block template the node serves, decoded into what a job is built from, with the rules that
//! decide whether work is served for it at all.

pub mod poller;
pub mod waker;

use ratum::datum::messages::validation::MAX_SHORT_LIST_TXNS;

const HASH_HEX_CHARS: std::ops::RangeInclusive<usize> = 64..=64;
const BITS_HEX_CHARS: std::ops::RangeInclusive<usize> = 8..=8;
const WITNESS_COMMITMENT_HEX_CHARS: std::ops::RangeInclusive<usize> = 38..=95;

#[derive(Clone, Debug)]
pub struct Txn {
    pub raw: Vec<u8>,
    pub txid: [u8; 32],
    pub witness_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TxnTotals {
    pub fee: u64,
    pub weight: u32,
    pub size: u32,
    pub sigops: u32,
}

#[derive(Clone, Debug)]
pub struct Template {
    pub height: u32,
    pub coinbase_value: u64,
    pub mintime: u64,
    pub curtime: u64,
    pub sizelimit: u64,
    pub weightlimit: u64,
    pub sigoplimit: u64,
    pub version: u32,
    pub nbits: u32,
    pub prev_hash: [u8; 32],
    pub witness_commitment: Vec<u8>,
    pub blake2b_rule: bool,
    pub reduced_data: bool,
    pub txns: Vec<Txn>,
    pub totals: TxnTotals,
}

impl Template {
    pub fn witness_hashes(&self) -> Vec<[u8; 32]> {
        self.txns.iter().map(|t| t.witness_hash).collect()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    #[error("missing or malformed {0} in the GBT JSON")]
    Field(&'static str),
    #[error("{0}")]
    Refused(String),
    #[error(
        "DATUM Gateway does not support blocks with more than {} transactions",
        MAX_SHORT_LIST_TXNS
    )]
    TooManyTxns,
}

fn u64_field(v: &serde_json::Value, key: &'static str) -> Result<u64, TemplateError> {
    match v[key].as_u64() {
        Some(n) if n != 0 => Ok(n),
        _ => Err(TemplateError::Field(key)),
    }
}

fn str_field<'a>(
    v: &'a serde_json::Value,
    key: &'static str,
    len: std::ops::RangeInclusive<usize>,
) -> Result<&'a str, TemplateError> {
    match v[key].as_str() {
        Some(s) if len.contains(&s.len()) => Ok(s),
        _ => Err(TemplateError::Field(key)),
    }
}

fn hash_field(v: &serde_json::Value, key: &'static str) -> Result<[u8; 32], TemplateError> {
    ratum::bitcoin::hash_from_display_hex(str_field(v, key, HASH_HEX_CHARS)?)
        .ok_or(TemplateError::Field(key))
}

fn rule_present(v: &serde_json::Value, rule: &str) -> bool {
    v["rules"].as_array().is_some_and(|a| a.iter().any(|r| r.as_str() == Some(rule)))
}

/// The template `v` carries, refused when the node enforces the `reduced_data` rule and the
/// pool's payout output script is longer than that rule admits: a coinbase paying it would be
/// rejected, so no work is served for the block.
pub fn parse(v: &serde_json::Value, payout_script: &[u8]) -> Result<Template, TemplateError> {
    let t = decode(v)?;
    if t.reduced_data && !ratum::bitcoin::script::output_script_size_is_valid(payout_script) {
        return Err(TemplateError::Refused(format!(
            "the pool payout output script is {} bytes, but the node enforces the reduced_data \
             rule for block {}, which limits a non-OP_RETURN coinbase output script to {} \
             bytes; serving no work for this block",
            payout_script.len(),
            t.height,
            ratum::bitcoin::script::MAX_OUTPUT_SCRIPT_SIZE
        )));
    }
    Ok(t)
}

fn decode(v: &serde_json::Value) -> Result<Template, TemplateError> {
    let height = u64_field(v, "height")? as u32;
    let coinbase_value = u64_field(v, "coinbasevalue")?;
    let mintime = u64_field(v, "mintime")?;
    let sigoplimit = u64_field(v, "sigoplimit")?;
    let curtime = u64_field(v, "curtime")?;
    let sizelimit = u64_field(v, "sizelimit")?;
    let weightlimit = u64_field(v, "weightlimit")?;
    let version = u64_field(v, "version")? as u32;
    let bits = str_field(v, "bits", BITS_HEX_CHARS)?;
    let wc_hex = str_field(v, "default_witness_commitment", WITNESS_COMMITMENT_HEX_CHARS)?;
    let witness_commitment =
        hex::decode(wc_hex).map_err(|_| TemplateError::Field("default_witness_commitment"))?;
    let nbits = u32::from_str_radix(bits, 16).map_err(|_| TemplateError::Field("bits"))?;
    let prev_hash = hash_field(v, "previousblockhash")?;
    let blake2b_rule = rule_present(v, "!blake2b");
    let reduced_data = rule_present(v, "reduced_data");

    let list = v["transactions"].as_array().ok_or(TemplateError::Field("transactions"))?;
    if list.len() > usize::from(MAX_SHORT_LIST_TXNS) {
        return Err(TemplateError::TooManyTxns);
    }
    let mut txns = Vec::with_capacity(list.len());
    let (mut fee, mut weight, mut size, mut sigops) = (0u64, 0u64, 0u64, 0u64);
    for t in list {
        let txid = hash_field(t, "txid")?;
        let witness_hash = hash_field(t, "hash")?;
        match t["fee"].as_i64() {
            Some(f) if f >= 0 => fee += f as u64,
            _ => {
                return Err(TemplateError::Refused(
                    "Missing or unknown fee in a GBT transaction; the coinbase value cannot be derived without it".into(),
                ));
            }
        }
        sigops += t["sigops"].as_u64().unwrap_or(0);
        weight += t["weight"].as_u64().unwrap_or(0);
        let raw = hex::decode(t["data"].as_str().ok_or(TemplateError::Field("data"))?)
            .map_err(|_| TemplateError::Field("data"))?;
        size += raw.len() as u64;
        txns.push(Txn { raw, txid, witness_hash });
    }

    Ok(Template {
        height,
        coinbase_value,
        mintime,
        curtime,
        sizelimit,
        weightlimit,
        sigoplimit,
        version,
        nbits,
        prev_hash,
        witness_commitment,
        blake2b_rule,
        reduced_data,
        txns,
        totals: TxnTotals { fee, weight: weight as u32, size: size as u32, sigops: sigops as u32 },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gbt(height: u64, rules: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "height": height,
            "coinbasevalue": 5000000000u64,
            "mintime": 1700000000u64,
            "sigoplimit": 80000,
            "curtime": 1700000100u64,
            "sizelimit": 4000000,
            "weightlimit": 4000000,
            "version": 536870912,
            "bits": "207fffff",
            "previousblockhash": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
            "target": "7fffff0000000000000000000000000000000000000000000000000000000000",
            "default_witness_commitment": "6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9",
            "rules": rules,
            "transactions": [],
        })
    }

    #[test]
    fn parses_a_template() {
        let t = parse(&gbt(20, &["segwit", "!blake2b"]), &[0; 22]).unwrap();
        assert_eq!(t.height, 20);
        assert_eq!(t.nbits, 0x207fffff);
        assert_eq!(t.nbits.to_le_bytes(), [0xff, 0xff, 0x7f, 0x20]);
        assert_eq!(t.prev_hash[31], 0x0f);
        assert_eq!(t.witness_commitment.len(), 38);
        assert!(t.blake2b_rule);
        assert!(!parse(&gbt(20, &["segwit"]), &[0; 22]).unwrap().blake2b_rule);
    }

    #[test]
    fn decodes_transactions_without_the_rule_checks() {
        let mut v = gbt(21, &["reduced_data"]);
        v["transactions"] = serde_json::json!([{
            "txid": "11".repeat(32), "hash": "22".repeat(32), "fee": 1000, "sigops": 4,
            "weight": 400, "data": "0100",
        }]);
        let t = decode(&v).unwrap();
        assert!(t.reduced_data, "the rule is read from the template, not passed in");
        assert_eq!(t.txns.len(), 1);
        assert_eq!(t.totals.fee, 1000);
        assert_eq!(t.totals.sigops, 4);
        assert_eq!(t.totals.weight, 400);
        assert_eq!(t.totals.size, 2);
        v["transactions"][0]["fee"] = serde_json::json!(-1);
        assert!(matches!(decode(&v), Err(TemplateError::Refused(_))));
    }

    #[test]
    fn reduced_data_refuses_an_oversized_payout_script() {
        let v = gbt(21, &["segwit", "!blake2b", "reduced_data"]);
        assert!(parse(&v, &[0; 35]).is_err());
        assert!(parse(&v, &[0; 34]).is_ok());
    }
}
