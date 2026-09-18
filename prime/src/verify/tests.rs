//! The share verifier's tests and the values they share: a policy, a job, a coinbase carrying the
//! pool's tag, and a share mined at difficulty 1 on it.

mod checks;
mod duplicates;
mod rebuild;
mod sections;
mod splits;

use super::jobs::{MAX_COINBASE_TYPES, MAX_RECENT_TIPS, TIP_GRACE_SECS, coinbase_bytes};
use super::rebuild::Payments;
use super::*;
use crate::abw::AbwSlotState;
use crate::fixtures::payout;
use ratum::bitcoin;
use ratum::bitcoin::transaction::CoinbaseTx;
use ratum::bitcoin::transaction::TxOut;
use ratum::datum::messages::abw::ASSIGNMENT_SLOTS;
use ratum::datum::messages::coinbaser::CoinbaserResponse;
use ratum::datum::messages::share;
use ratum::datum::messages::share::{
    COINBASE_ID_SUBSIDY_ONLY, CoinbaseSection, JobSection, MAX_COINBASE_SECTION_LEN,
};
use ratum::fixtures::{self, ScriptSigTags, p2wpkh};
use ratum::header::BlockHeaderV2;

const NAMES: &[&str] = &["alice", "bob"];

fn record(v: &mut Verifier, r: &CoinbaserResponse, identities: &[&str], now: u64) {
    let outputs = r
        .outputs
        .iter()
        .enumerate()
        .map(|(i, output)| DictatedOutput {
            payout: Payout {
                identity: identities.get(i).map_or_else(String::new, |id| id.to_string()),
                sats: output.value,
            },
            script_pubkey: output.script_pubkey.clone(),
        })
        .collect();
    v.record_dictated(r.coinbaser_id, outputs, now);
}

/// The policy the helpers below verify against, which outlives every `Verifier` they hand
/// back. A test that needs another policy owns it and passes `&p`.
fn shared_policy() -> &'static SharePolicy {
    static POLICY: std::sync::OnceLock<SharePolicy> = std::sync::OnceLock::new();
    POLICY.get_or_init(policy)
}

fn verifier() -> Verifier<'static> {
    Verifier::new(shared_policy())
}

const NOW: u64 = 1_760_000_000;

const NBITS: [u8; 4] = [0xff, 0xff, 0x7f, 0x20];

const COINBASE_VALUE: u64 = 312_500_000;

const EXTRANONCE: [u8; share::EXTRANONCE_SIZE] = [0x33; share::EXTRANONCE_SIZE];

const HARD_NBITS: [u8; 4] = [0xff, 0xff, 0x00, 0x1c];

const DIFF1_NONCE: u32 = 0x099c_1d0f;

const DIFF1_NONCE_HARD: u32 = 0x5823_2ac6;

fn policy() -> SharePolicy {
    SharePolicy {
        config: ClientConfig {
            payout_script: p2wpkh(0xee),
            prime_id: 0x0000_0001,
            coinbase_tag: "RATUM".to_string(),
            min_difficulty: 1,
            v3: None,
        },
        require_split: true,
        chain: Some(rpc::Chain::Regtest),
    }
}

fn coinbase_sections(p: &SharePolicy, outputs: &[TxOut]) -> (CoinbaseSection, usize) {
    let tagging = ScriptSigTags {
        tag_primary: &p.config.coinbase_tag,
        tag_secondary: "",
        prime_id: p.config.prime_id as u32,
    };
    let built = fixtures::coinbase(&tagging, &p.config.payout_script, outputs, COINBASE_VALUE);
    (built.section, built.target_byte_index)
}

fn job_section(target_byte_index: usize) -> JobSection {
    JobSection {
        prev_hash: [0x5a; 32],
        target_byte_index: target_byte_index as u16,
        nbits: NBITS,
        coinbaser_id: 1,
        height: 840_000,
        coinbase_value: COINBASE_VALUE,
        txn_count: 0,
        txn_total_weight: 0,
        txn_total_size: 0,
        txn_total_sigops: 0,
        merkle_branches: vec![],
    }
}

fn split() -> CoinbaserResponse {
    CoinbaserResponse {
        value: COINBASE_VALUE,
        coinbaser_id: 1,
        outputs: vec![
            TxOut { value: 100_000_000, script_pubkey: p2wpkh(0x01) },
            TxOut { value: 50_000_000, script_pubkey: p2wpkh(0x02) },
        ],
    }
}

fn section(time_on_wire: u32, nonce: u32) -> share::Blake2bSection {
    let mut sia_nonce = [0u8; 8];
    sia_nonce[..4].copy_from_slice(&nonce.to_le_bytes());
    share::Blake2bSection { sia_ntime: [0u8; 8], sia_nonce, time_on_wire }
}

fn share_on(job: JobSection, cb: CoinbaseSection) -> PowSubmit {
    let time_on_wire = NOW as u32;
    PowSubmit {
        job_id: 0,
        coinbase_id: 0,
        is_block: false,
        subsidy_only: false,
        quickdiff: false,
        target_byte: 0,
        ntime: time_on_wire,
        nonce: DIFF1_NONCE,
        version: header::V2_FLAG | 0x2000_0000,
        extranonce: EXTRANONCE,
        username: "bc1qexample.worker1".to_string(),
        use_time_offset: false,
        job: Some(job),
        coinbase: Some(cb),
        blake2b: section(time_on_wire, DIFF1_NONCE),
        abw_slot: None,
    }
}

fn setup() -> (Verifier<'static>, PowSubmit) {
    with_outputs(&split().outputs)
}

fn setup_hard() -> (Verifier<'static>, PowSubmit) {
    let (mut v, mut s) = with_outputs(&split().outputs);
    let mut job = s.job.clone().unwrap();
    job.nbits = HARD_NBITS;
    s.job = Some(job);
    let time_on_wire = NOW as u32;
    s.nonce = DIFF1_NONCE_HARD;
    s.ntime = time_on_wire;
    s.blake2b = section(time_on_wire, DIFF1_NONCE_HARD);
    v.set_next_bits(Some(u32::from_le_bytes(HARD_NBITS)));
    (v, s)
}

fn with_outputs(outputs: &[TxOut]) -> (Verifier<'static>, PowSubmit) {
    let p = shared_policy();
    let (cb, target_byte_index) = coinbase_sections(p, outputs);
    let mut v = Verifier::new(p);
    record(&mut v, &split(), &[], NOW);
    v.set_next_bits(Some(u32::from_le_bytes(NBITS)));
    (v, share_on(job_section(target_byte_index), cb))
}

fn built_header(rebuilt: &RebuiltShare) -> BlockHeaderV2 {
    BlockHeaderV2::deserialize(&rebuilt.header).expect("a version 2 header")
}

impl Verifier<'_> {
    /// `verify` with the refusal reduced to its reason.
    fn checked(
        &mut self,
        s: &PowSubmit,
        abw: Option<&AbwSlotState>,
        now: u64,
    ) -> Result<RebuiltShare, RejectReason> {
        self.verify(s, abw, now).map_err(|refusal| refusal.reason)
    }
}
