//! The coinbase split the pool dictates for one job: what each miner in the payout window
//! is owed of the job's value, cut down to what one coinbaser message can carry.

use crate::server::{Server, dictated_outputs};
use log::{error, info, warn};
use ratum::datum::messages::{CoinbaseOutput, CoinbaserResponse};
use ratum::lock;
use std::io;
use std::net::SocketAddr;

/// How far a gateway's stated coinbase value may sit from what this node's own template
/// pays before the pool refuses to dictate a split for it, as a factor either way.
const COINBASE_VALUE_TOLERANCE: f64 = 2.0;

/// A dictated split: the response to send, the identity behind each output it kept, and
/// the encoded message.
pub(crate) struct Split {
    pub(crate) response: CoinbaserResponse,
    pub(crate) identities: Vec<String>,
    pub(crate) payload: Vec<u8>,
}

/// Whether `value` is close enough to what this node's template pays to dictate a split
/// for. A node with no template of its own accepts any value.
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

/// The next coinbaser id, which is never 0: a share whose job carries id 0 is one the
/// gateway built without asking for a split.
pub(crate) fn next_id(current: u8) -> u8 {
    match current.wrapping_add(1) {
        0 => 1,
        next => next,
    }
}

/// Splits `value` over the payout window and encodes the result. Outputs are removed from
/// the end until the message fits; if even one does not fit, the whole value goes to the
/// pool's payout script.
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

/// The identity each kept output pays. `dictated` is in the same order as the outputs it
/// produced, so one forward pass matches them; an output with no match (the fallback to
/// the pool's own script) is named by the empty string.
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
