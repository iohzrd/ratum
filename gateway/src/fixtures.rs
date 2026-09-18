//! Test values the gateway's own tests build on: a minimal configuration, a template, a job and a
//! gateway.

use crate::config::Config;
use crate::gateway::Gateway;
use crate::job::Job;
use crate::job::builder::{JobInputs, build};
use crate::template::{Template, TxnTotals};
use std::sync::Arc;

pub fn config() -> Config {
    Config::parse(
        r#"{
          "bitcoind": {"rpcuser":"u","rpcpassword":"p","rpcurl":"http://127.0.0.1:1"},
          "mining": {"pool_address":"bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"},
          "datum": {"pool_host": "", "pooled_mining_only": false, "protocol_job_slots": 6}
        }"#,
    )
    .unwrap()
}

pub use ratum::fixtures::hash;

pub fn template() -> Template {
    let mut wc = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    wc.extend_from_slice(&[0u8; 32]);
    Template {
        height: 21,
        coinbase_value: 5_000_000_000,
        mintime: 1_700_000_000,
        curtime: 1_700_000_100,
        sizelimit: 4_000_000,
        weightlimit: 4_000_000,
        sigoplimit: 80_000,
        version: 0x2000_0000,
        nbits: 0x207f_ffff,
        prev_hash: [0u8; 32],
        witness_commitment: wc,
        blake2b_rule: true,
        reduced_data: false,
        txns: vec![],
        totals: TxnTotals::default(),
    }
}

pub fn job_with_id(stratum_job_id: &str) -> Job {
    let mut job = build(&config(), JobInputs::new(0, Arc::new(template()))).unwrap();
    job.stratum_job_id = stratum_job_id.to_string();
    job
}

pub fn test_gateway(edit: impl FnOnce(&mut Config)) -> Arc<Gateway> {
    let mut config = config();
    edit(&mut config);
    let node = ratum::rpc::Client::new("http://127.0.0.1:1", "u", "p", None).unwrap();
    Gateway::new(config, node)
}
