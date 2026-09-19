//! The split as outputs: each identity's address decoded to the script that pays it, the ones no
//! address decodes left with the pool, and the coinbaser response carrying the rest.

use crate::ledger::split::Payout;
use crate::server::Server;
use log::{info, warn};
use ratum::bitcoin::address;
use ratum::bitcoin::transaction::TxOut;
use ratum::datum::messages::coinbaser::{
    CoinbaserResponse, MAX_COINBASER_BLOB_LEN, MAX_COINBASER_OUTPUT_SCRIPT_LEN,
    MAX_COINBASER_OUTPUTS,
};
use ratum::{lock, rpc};
use std::net::SocketAddr;

const COINBASE_VALUE_TOLERANCE: f64 = 2.0;

/// A split of at most `MAX_COINBASER_OUTPUTS` outputs of address scripts fits the message,
/// so `CoinbaserResponse::encode` refuses no split `dictated_outputs` produces.
const _: () = assert!(
    address::MAX_SCRIPT_LEN <= MAX_COINBASER_OUTPUT_SCRIPT_LEN
        && size_of::<u8>()
            + MAX_COINBASER_OUTPUTS * (size_of::<u64>() + 1 + address::MAX_SCRIPT_LEN)
            <= MAX_COINBASER_BLOB_LEN
);

const ADDRESS_TYPES: &str = "P2PKH, P2SH, P2WPKH, P2WSH or P2TR";

/// What one identity is paid and the script paying it: the `Payout` the split produced,
/// plus the output script `address_script` decoded its identity to. Holding the payout
/// rather than restating its fields is what lets the owed path take it back without
/// rebuilding it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DictatedOutput {
    pub payout: Payout,
    pub script_pubkey: Vec<u8>,
}

impl DictatedOutput {
    pub fn output(&self) -> TxOut {
        TxOut { value: self.payout.sats, script_pubkey: self.script_pubkey.clone() }
    }
}

/// The script paid to `address` (a miner's identity or `--payout-address`): none unless it is
/// a P2PKH, P2SH, P2WPKH, P2WSH or P2TR address with the prefixes of `chain`, the chain the
/// node reported at startup, or with those of any chain when `chain` is none or has no known
/// prefixes.
pub fn address_script(address: &str, chain: Option<rpc::Chain>) -> Option<Vec<u8>> {
    address::to_output_script(address, chain.and_then(rpc::Chain::address_prefixes))
}

/// Why `address_script` gives no script on `chain`.
pub fn unpayable_reason(chain: Option<rpc::Chain>) -> String {
    match chain.filter(|c| c.address_prefixes().is_some()) {
        Some(chain) => format!("not a {ADDRESS_TYPES} address of chain {}", chain.name()),
        None => format!("not a {ADDRESS_TYPES} address"),
    }
}

/// The split of `value` (`Weights::split`) as outputs. The ledger lock is held only to copy
/// the window's weights (`Ledger::weights_for`): the sort, the amounts and the address
/// decoding run without it.
pub fn dictated_outputs(server: &Server, value: u64) -> Vec<DictatedOutput> {
    let (weights, value) = lock(&server.ledger).weights_for(value);
    outputs_for(weights.split(value), server.share_policy.chain)
}

/// The split as outputs to the identities `address_script` gives a script for; the others are
/// logged and left to the pool's script as the remainder.
fn outputs_for(split: Vec<Payout>, chain: Option<rpc::Chain>) -> Vec<DictatedOutput> {
    let mut kept = Vec::with_capacity(split.len());
    for payout in split {
        match address_script(&payout.identity, chain) {
            Some(script) => kept.push(DictatedOutput { payout, script_pubkey: script }),
            None => warn!(
                "      {} cannot be paid ({}); its {} sats are left out of the split and stay \
                 with the pool",
                payout.identity,
                unpayable_reason(chain),
                payout.sats
            ),
        }
    }
    kept
}

/// Whether a gateway's coinbase value is within a factor of `COINBASE_VALUE_TOLERANCE` of the
/// node's template; true while the node has given no template.
pub fn value_is_plausible(server: &Server, peer: SocketAddr, value: u64) -> bool {
    let Some(reference) = server.node_state.coinbase_value() else { return true };
    let low = (reference as f64 / COINBASE_VALUE_TOLERANCE) as u64;
    let high = (reference as f64 * COINBASE_VALUE_TOLERANCE) as u64;
    if (low..=high).contains(&value) {
        return true;
    }
    warn!(
        "[{peer}]      refusing a split for {value} sats: this node's template pays \
         {reference} sats"
    );
    false
}

/// The outputs dictated for `value` and the coinbaser response carrying them.
pub fn dictate(
    server: &Server,
    peer: SocketAddr,
    value: u64,
    coinbaser_id: u8,
) -> (Vec<DictatedOutput>, Vec<u8>) {
    let (weights, miners_value, window_shares, window_work) = {
        let l = lock(&server.ledger);
        let (weights, miners_value) = l.weights_for(value);
        (weights, miners_value, l.len(), l.total_work())
    };
    let dictated = outputs_for(weights.split(miners_value), server.share_policy.chain);
    let paid: u64 = dictated.iter().map(|d| d.payout.sats).sum();
    info!(
        "[{peer}]      paying {} miners {paid} of {value} sats from a window of {window_shares} \
         shares ({window_work} work)",
        dictated.len(),
    );
    let outputs = dictated.iter().map(DictatedOutput::output).collect();
    let payload = CoinbaserResponse { value, coinbaser_id, outputs }
        .encode()
        .expect("a split of payable outputs totalling at most the value encodes");
    (dictated, payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{
        ALICE, BOB, POOL, server_with, server_with_fee, server_with_public_gateway_fee,
    };
    use crate::ledger::split::SplitPolicy;
    use ratum::fixtures::p2wpkh;

    const MAIN_ADDRESS: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

    fn coinbaser_outputs(server: &Server, value: u64) -> Vec<TxOut> {
        dictated_outputs(server, value).iter().map(DictatedOutput::output).collect()
    }

    #[test]
    fn an_address_is_paid_when_it_carries_the_prefixes_of_the_nodes_chain() {
        let regtest = Some(rpc::Chain::Regtest);
        assert_eq!(address_script(ALICE, regtest), Some(p2wpkh(0xa1)));
        assert_eq!(address_script(BOB, regtest), Some(p2wpkh(0xb2)));
        assert_eq!(address_script(MAIN_ADDRESS, regtest), None, "a mainnet address");
        assert!(address_script(MAIN_ADDRESS, None).is_some(), "no chain read at startup");
        assert!(
            address_script(MAIN_ADDRESS, Some(rpc::Chain::Other)).is_some(),
            "a chain with no known prefixes"
        );
        assert_eq!(
            unpayable_reason(regtest),
            "not a P2PKH, P2SH, P2WPKH, P2WSH or P2TR address of chain regtest"
        );
        assert_eq!(unpayable_reason(None), "not a P2PKH, P2SH, P2WPKH, P2WSH or P2TR address");
        assert_eq!(unpayable_reason(Some(rpc::Chain::Other)), unpayable_reason(None));
    }

    #[test]
    fn a_split_names_every_miner_and_never_the_pool() {
        let server = server_with(&[(ALICE, 3), (BOB, 1)]);
        let outputs = coinbaser_outputs(&server, 1_000_000);
        assert_eq!(
            outputs.iter().map(|o| (o.value, o.script_pubkey.clone())).collect::<Vec<_>>(),
            vec![(750_000, p2wpkh(0xa1)), (250_000, p2wpkh(0xb2))]
        );
        assert_eq!(outputs.iter().map(|o| o.value).sum::<u64>(), 1_000_000);
        assert!(outputs.iter().all(|o| o.script_pubkey != POOL));
    }

    #[test]
    fn a_fee_is_deducted_before_the_split_and_left_to_the_pool() {
        let server = server_with_fee(&[(ALICE, 3), (BOB, 1)], 100);
        let outputs = coinbaser_outputs(&server, 1_000_000);
        assert_eq!(
            outputs.iter().map(|o| (o.value, o.script_pubkey.clone())).collect::<Vec<_>>(),
            vec![(742_500, p2wpkh(0xa1)), (247_500, p2wpkh(0xb2))]
        );
        let paid: u64 = outputs.iter().map(|o| o.value).sum();
        assert_eq!(paid, 990_000);
        assert_eq!(1_000_000 - paid, 10_000);
        assert!(outputs.iter().all(|o| o.script_pubkey != POOL));
    }

    fn with_bps(fee_bps: u16) -> SplitPolicy {
        SplitPolicy { fee_bps, ..SplitPolicy::default() }
    }

    #[test]
    fn the_fee_is_rounded_down_so_the_operator_never_over_takes() {
        assert_eq!(with_bps(0).fee_on(1_000_000), 0, "no fee by default");
        assert_eq!(with_bps(50).fee_on(1_000_000), 5_000, "0.5%");
        assert_eq!(with_bps(100).fee_on(1_000_000), 10_000);
        assert_eq!(with_bps(100).fee_on(1), 0);
    }

    #[test]
    fn an_empty_window_names_nobody() {
        let server = server_with(&[]);
        assert!(coinbaser_outputs(&server, 1_000_000).is_empty());
    }

    #[test]
    fn an_identity_that_is_not_an_address_of_the_chain_leaves_its_amount_to_the_pool() {
        for unpayable in ["nonsense", MAIN_ADDRESS] {
            let server = server_with(&[(ALICE, 3), (unpayable, 1)]);
            let outputs = coinbaser_outputs(&server, 1_000_000);
            assert_eq!(outputs.len(), 1, "{unpayable}");
            assert_eq!(outputs[0].script_pubkey, p2wpkh(0xa1));
            assert_eq!(outputs[0].value, 750_000);
            assert_eq!(1_000_000 - outputs[0].value, 250_000);
        }
    }

    #[test]
    fn the_dictated_split_charges_the_public_gateway_fee_and_reassigns_it() {
        let server = server_with_public_gateway_fee(5_000, 10_000);
        let outputs = coinbaser_outputs(&server, 200_000);
        assert_eq!(
            outputs.iter().map(|o| (o.value, o.script_pubkey.clone())).collect::<Vec<_>>(),
            vec![(150_000, p2wpkh(0xb2)), (50_000, p2wpkh(0xa1))]
        );

        let off = server_with_public_gateway_fee(0, 0);
        let outputs = coinbaser_outputs(&off, 200_000);
        assert_eq!(outputs.iter().map(|o| o.value).collect::<Vec<_>>(), vec![100_000, 100_000]);
    }

    #[test]
    fn the_minimum_is_applied_before_the_identities_are_decoded() {
        let server = server_with(&[(ALICE, 999), (BOB, 1)]);
        let outputs = coinbaser_outputs(&server, 500_000);
        assert_eq!(outputs.len(), 1, "bob's 500 is under the minimum");
        assert_eq!(outputs[0].value, 500_000);
    }
}
