use crate::server::{Server, dictated_outputs};
use log::{error, info, warn};
use ratum::datum::messages::{CoinbaseOutput, CoinbaserResponse};
use ratum::lock;
use std::io;
use std::net::SocketAddr;

const COINBASE_VALUE_TOLERANCE: f64 = 2.0;

pub(crate) struct Split {
    pub(crate) response: CoinbaserResponse,
    pub(crate) identities: Vec<String>,
    pub(crate) payload: Vec<u8>,
}

pub(crate) fn value_is_plausible(server: &Server, peer: SocketAddr, value: u64) -> bool {
    let Some(reference) = *lock(&server.node_view.coinbase_value) else { return true };
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

pub(crate) fn next_id(current: u8) -> u8 {
    match current.wrapping_add(1) {
        0 => 1,
        next => next,
    }
}

pub(crate) fn dictate(
    server: &Server,
    peer: SocketAddr,
    value: u64,
    coinbaser_id: u8,
) -> io::Result<Split> {
    let (dictated, shares, work) = dictated_outputs(server, value);
    let paid: u64 = dictated.iter().map(|(_, o)| o.value).sum();
    let outputs: Vec<CoinbaseOutput> = dictated.iter().map(|(_, o)| o.clone()).collect();
    info!(
        "[{peer}]      paying {} miners {paid} of {value} sats from a window of {shares} \
         shares ({work} work)",
        outputs.len()
    );

    let mut response = CoinbaserResponse { value, coinbaser_id, outputs };
    let removed = response.retain_payable();
    if removed != 0 {
        warn!("[{peer}]      removed {removed} unpayable outputs from the split");
    }
    let payload = encode_shrinking(server, peer, &mut response)?;
    let identities = identities_of(&response, &dictated);
    Ok(Split { response, identities, payload })
}

fn encode_shrinking(
    server: &Server,
    peer: SocketAddr,
    response: &mut CoinbaserResponse,
) -> io::Result<Vec<u8>> {
    loop {
        match response.encode() {
            Ok(payload) => return Ok(payload),
            Err(e) if response.outputs.len() > 1 => {
                let removed = response.outputs.pop();
                warn!(
                    "[{peer}]      split too large ({e}); removed an output of {} sats",
                    removed.map_or(0, |o| o.value)
                );
            }
            Err(e) => {
                error!("[{peer}]      could not build the split ({e}); paying the pool");
                response.outputs = vec![CoinbaseOutput {
                    value: response.value,
                    script: server.policy.payout_script.clone(),
                }];
                return response.encode().map_err(|e| io::Error::other(e.to_string()));
            }
        }
    }
}

fn identities_of(
    response: &CoinbaserResponse,
    dictated: &[(String, CoinbaseOutput)],
) -> Vec<String> {
    let mut rest = dictated.iter();
    response
        .outputs
        .iter()
        .map(|o| {
            rest.by_ref()
                .find(|(_, d)| d.value == o.value && d.script == o.script)
                .map_or_else(String::new, |(identity, _)| identity.clone())
        })
        .collect()
}
