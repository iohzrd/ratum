//! Building the work a gateway would send: a coinbase split in two around the extranonce,
//! the job that describes it, and the version 2 header built from them (the coinbase's
//! merkle root and the job's fields).
//!
//! The pool rebuilds all of this from the share and compares; anything these helpers get
//! wrong produces a rejection, which is what makes them useful as a test fixture.

#![allow(dead_code)]

use ratum::bitcoin;
use ratum::datum::messages::CoinbaseOutput;
use ratum::datum::share::{self, CoinbaseSection, JobSection, PowSubmit};
use ratum::header::HeaderV2;
// Re-exported so test files reach the fixtures through one path; not every test binary
// uses both names.
#[allow(unused_imports)]
pub use ratum::fixtures::{Tagging, p2wpkh};

pub const COINBASE_VALUE: u64 = 312_500_000;

/// The tip these jobs build on. A pool with a node treats a job on a different tip as stale,
/// so the stand-in node reports this one.
pub const PREV_HASH: [u8; 32] = [0x5a; 32];
/// Regtest's proof-of-work limit (`powLimit`, nBits 0x207fffff): half of all hashes meet this
/// network target, so a share that meets the share target (diff 1, 2^224) is also a block.
pub const EASY_NBITS: [u8; 4] = [0xff, 0xff, 0x7f, 0x20];
/// A network target no test share will meet, for separating "share" from "block".
pub const HARD_NBITS: [u8; 4] = [0xff, 0xff, 0x00, 0x1c];

pub struct Work {
    pub cb: CoinbaseSection,
    pub job: JobSection,
    pub pot_index: usize,
    /// The twelve extranonce bytes a share sends, restored into the header's 16-byte field.
    pub extranonce: [u8; share::EXTRANONCE_SIZE],
    pub payout_script: Vec<u8>,
}

impl Work {
    /// Work whose coinbase pays `outputs` and gives the rest to `payout_script`.
    pub fn build(
        tagging: &Tagging,
        payout_script: &[u8],
        outputs: &[CoinbaseOutput],
        coinbase_value: u64,
    ) -> Self {
        let (cb, pot_index) =
            ratum::fixtures::coinbase(tagging, payout_script, outputs, coinbase_value);

        let job = JobSection {
            prev_hash: PREV_HASH,
            target_byte_index: pot_index as u16,
            nbits: EASY_NBITS,
            coinbaser_id: 1,
            height: 840_000,
            coinbase_value,
            txn_count: 0,
            txn_total_weight: 0,
            txn_total_size: 0,
            txn_total_sigops: 0,
            merkle_branches: vec![],
        };

        Work {
            cb,
            job,
            pot_index,
            extranonce: [7u8; share::EXTRANONCE_SIZE],
            payout_script: payout_script.to_vec(),
        }
    }

    /// The coinbase as the pool rebuilds it: twelve zero bytes where the upstream format
    /// splices the extranonce (the header carries it instead), and the target byte written.
    pub fn full_coinbase(&self, target_byte: u8) -> Vec<u8> {
        let mut full = self.cb.assemble(&[0u8; share::EXTRANONCE_SIZE]);
        full[self.pot_index] = target_byte;
        full
    }

    pub fn merkle_root(&self, target_byte: u8) -> [u8; 32] {
        let coinbase = self.full_coinbase(target_byte);
        bitcoin::merkle_root(&bitcoin::sha256d(&coinbase), &self.job.merkle_branches)
    }

    /// A profile-0 header for this work: the layout a Sia-dialect ASIC hashes, with no
    /// time offset, no merge-mining commitment (`mm_rhs` zero) and a zero XOR key.
    pub fn header(&self, ntime: u32, nonce: u32, target_byte: u8) -> HeaderV2 {
        HeaderV2 {
            version: 0x2000_0000,
            prev_block: self.job.prev_hash,
            merkle_root: self.merkle_root(target_byte),
            time: ntime,
            bits: u32::from_le_bytes(self.job.nbits),
            nonce,
            nonce2: 0,
            nonce3: 0,
            extranonce: share::header_extranonce(&self.extranonce).expect("twelve bytes"),
            time_offset: 0,
            txcount: self.job.txn_count as u16 + 1,
            flags: 0,
            xor_key_mask_clear_bits: 0,
            xor_key: [0u8; 16],
            height: self.job.height as i32,
            mm_rhs: [0u8; 32],
        }
    }

    /// The hash the pool will compute, in the order it compares against a target.
    pub fn hash(&self, ntime: u32, nonce: u32, target_byte: u8) -> [u8; 32] {
        self.header(ntime, nonce, target_byte).hash_components().result
    }

    /// A share for this work: the fields the miner sets are sent, and the pool builds the
    /// header from them and the job. `header` above is the header the pool should build.
    pub fn submit(&self, username: &str, ntime: u32, nonce: u32, target_byte: u8) -> PowSubmit {
        PowSubmit {
            job_id: 0,
            coinbase_id: self.cb.coinbase_id,
            is_block: false,
            subsidy_only: false,
            quickdiff: false,
            target_byte,
            ntime,
            nonce,
            version: ratum::header::V2_FLAG | 0x2000_0000,
            extranonce: self.extranonce.to_vec(),
            username: username.to_string(),
            job: Some(self.job.clone()),
            coinbase: Some(self.cb.clone()),
            use_time_offset: false,
            blake2b: Self::blake2b_section_of(ntime, nonce),
        }
    }

    /// The section a profile-0 share carries: the raw Sia fields, with `m_nonce2`,
    /// `m_nonce3` and the time offset all zero, and no time-offset flag.
    fn blake2b_section_of(ntime: u32, nonce: u32) -> share::Blake2bSection {
        let mut sia_nonce = [0u8; 8];
        sia_nonce[..4].copy_from_slice(&nonce.to_le_bytes());
        share::Blake2bSection { sia_ntime: [0u8; 8], sia_nonce, time_on_wire: ntime }
    }

    /// Search the nonce space for a hash that meets `target`. Only the four nonce bytes of
    /// the 80-byte ASIC input change, so everything before it is computed once, the same
    /// layout the hardware hashes.
    pub fn find_nonce(&self, ntime: u32, target_byte: u8, target: &[u8; 32]) -> Option<u32> {
        let header = self.header(ntime, 0, target_byte);
        let pre = header.precompute();
        let input = header.asic_input_with(&pre.hash1, &pre.h2);
        // The proof of work is compared as it comes out of BLAKE2b, not reversed the way a
        // SHA256d block hash is.
        ratum::nonce::search(&input, 32, ratum::header::blake2b_256, target, || false)
    }
}
