use crate::cursor::Cursor;

/// The first payload byte of a `cmd::MINING` frame sent by the pool: the mining sub-command.
pub mod server_subcmd {
    pub const CONFIG: u8 = 0x99;
    pub const COINBASER: u8 = 0x11;
    pub const VALIDATION: u8 = 0x50;
    pub const SHARE_RESPONSE: u8 = 0x8F;
    pub const BLOCKNOTIFY: u8 = 0xF9;
}

/// The first payload byte of a `cmd::MINING` frame sent by the gateway: the mining sub-command.
pub mod client_subcmd {
    pub const COINBASER_REQUEST: u8 = 0x10;
    pub const SUBMIT_POW: u8 = 0x27;
    pub const VALIDATION: u8 = 0x50;
}

pub use super::framing::STRUCT_END;
pub const CONFIG_VERSION: u8 = 1;
/// The gateway's `pool_addr_script` field (`T_DATUM_STRATUM_JOB`, `src/datum_stratum.h`).
/// A longer script has nowhere to go: the gateway copies it into every stratum job and
/// writes it into the generation transaction verbatim, so it cannot be truncated to fit.
pub const MAX_PAYOUT_SCRIPT: usize = 64;
/// One less than the gateway's parser accepts (255, into a 256-byte buffer).
pub const MAX_COINBASE_TAG: usize = 254;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("{field} too long: {len} bytes")]
    TooLong { field: &'static str, len: usize },
    #[error("{field} length {len} is out of range")]
    OutOfRange { field: &'static str, len: usize },
    #[error("min difficulty {0} is not a power of two")]
    MinDiffNotPowerOfTwo(u64),
    #[error("payout split totals {total} sats, exceeding the job's {value}")]
    SplitExceedsValue { total: u64, value: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientConfig {
    pub payout_script: Vec<u8>,
    pub prime_id: u32,
    pub coinbase_tag: String,
    pub min_difficulty: u64,
}

impl ClientConfig {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.payout_script.len() > MAX_PAYOUT_SCRIPT {
            return Err(Error::TooLong { field: "payout script", len: self.payout_script.len() });
        }
        if self.coinbase_tag.len() > MAX_COINBASE_TAG {
            return Err(Error::TooLong { field: "coinbase tag", len: self.coinbase_tag.len() });
        }
        if !self.min_difficulty.is_power_of_two() {
            return Err(Error::MinDiffNotPowerOfTwo(self.min_difficulty));
        }

        let tag = self.coinbase_tag.as_bytes();
        let mut out = Vec::with_capacity(16 + self.payout_script.len() + tag.len());
        out.push(server_subcmd::CONFIG);
        out.push(CONFIG_VERSION);
        out.push(self.payout_script.len() as u8);
        out.extend_from_slice(&self.payout_script);
        out.extend_from_slice(&self.prime_id.to_le_bytes());
        out.push(tag.len() as u8);
        out.extend_from_slice(tag);
        out.extend_from_slice(&self.min_difficulty.to_le_bytes());
        out.push(0);
        out.push(STRUCT_END);
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut c = Cursor::new(data);
        c.skip_if(server_subcmd::CONFIG);
        if c.u8("version").ok()? != CONFIG_VERSION {
            return None;
        }
        let a = c.u8("script length").ok()? as usize;
        if a > MAX_PAYOUT_SCRIPT {
            return None;
        }
        let payout_script = c.take(a, "payout script").ok()?.to_vec();
        let prime_id = c.u32("prime id").ok()?;
        let b = c.u8("tag length").ok()? as usize;
        let coinbase_tag = String::from_utf8_lossy(c.take(b, "coinbase tag").ok()?).into_owned();
        let min_difficulty = c.u64("min difficulty").ok()?;
        if c.arr("terminator").ok()? != [0, STRUCT_END] {
            return None;
        }
        Some(ClientConfig { payout_script, prime_id, coinbase_tag, min_difficulty })
    }
}

pub const MAX_COINBASER_BLOB: usize = 32767;
pub const MIN_OUTPUT_SCRIPT: usize = 2;
pub const MAX_OUTPUT_SCRIPT: usize = 64;
pub const MAX_COINBASER_OUTPUTS: usize = 512;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinbaserRequest {
    pub value: u64,
    pub prev_hash: [u8; 32],
}

impl CoinbaserRequest {
    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut c = Cursor::new(data);
        c.skip_if(client_subcmd::COINBASER_REQUEST);
        let value = c.u64("value").ok()?;
        let prev_hash: [u8; 32] = c.arr("prev hash").ok()?;
        if c.u8("terminator").ok()? != STRUCT_END {
            return None;
        }
        Some(CoinbaserRequest { value, prev_hash })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(42);
        out.push(client_subcmd::COINBASER_REQUEST);
        out.extend_from_slice(&self.value.to_le_bytes());
        out.extend_from_slice(&self.prev_hash);
        out.push(STRUCT_END);
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinbaseOutput {
    pub value: u64,
    pub script: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinbaserResponse {
    pub value: u64,
    pub coinbaser_id: u8,
    pub outputs: Vec<CoinbaseOutput>,
}

impl CoinbaserResponse {
    /// Removes zero-value outputs (a RATUM rule; the gateway accepts them), outputs whose script
    /// length is outside 2..=64 (one such output makes the gateway discard the whole coinbaser),
    /// and outputs past the 512 the gateway parses. Returns how many were removed.
    pub fn retain_payable(&mut self) -> usize {
        let before = self.outputs.len();
        self.outputs.retain(|o| {
            o.value > 0 && (MIN_OUTPUT_SCRIPT..=MAX_OUTPUT_SCRIPT).contains(&o.script.len())
        });
        if self.outputs.len() > MAX_COINBASER_OUTPUTS {
            self.outputs.truncate(MAX_COINBASER_OUTPUTS);
        }
        before - self.outputs.len()
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.outputs.len() > MAX_COINBASER_OUTPUTS {
            return Err(Error::TooLong { field: "coinbaser outputs", len: self.outputs.len() });
        }
        let mut blob = Vec::with_capacity(1 + self.outputs.len() * 41);
        blob.push(self.coinbaser_id);
        let mut total: u64 = 0;
        for o in &self.outputs {
            if o.script.len() < MIN_OUTPUT_SCRIPT || o.script.len() > MAX_OUTPUT_SCRIPT {
                return Err(Error::OutOfRange { field: "output script", len: o.script.len() });
            }
            total = total.saturating_add(o.value);
            blob.extend_from_slice(&o.value.to_le_bytes());
            blob.push(o.script.len() as u8);
            blob.extend_from_slice(&o.script);
        }
        if total > self.value {
            return Err(Error::SplitExceedsValue { total, value: self.value });
        }
        if blob.len() > MAX_COINBASER_BLOB {
            return Err(Error::TooLong { field: "coinbaser blob", len: blob.len() });
        }

        let mut out = Vec::with_capacity(13 + blob.len());
        out.push(server_subcmd::COINBASER);
        out.extend_from_slice(&self.value.to_le_bytes());
        out.extend_from_slice(&(blob.len() as u32).to_le_bytes());
        out.extend_from_slice(&blob);
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        Self::decode_with(data, &|_| false)
    }

    /// Decode, leaving out every output whose script `skip` names, before its value counts
    /// toward the total (the C gateway's `reduced_data` check in `datum_coinbaser_v2_parse`).
    pub fn decode_with(data: &[u8], skip: &dyn Fn(&[u8]) -> bool) -> Option<Self> {
        let mut c = Cursor::new(data);
        c.skip_if(server_subcmd::COINBASER);
        let value = c.u64("value").ok()?;
        let blob_len = c.u32("blob length").ok()? as usize;
        if !(1..=MAX_COINBASER_BLOB).contains(&blob_len) {
            return None;
        }
        let mut b = Cursor::new(c.take(blob_len, "blob").ok()?);
        let coinbaser_id = b.u8("coinbaser id").ok()?;
        let mut outputs = Vec::new();
        let mut total: u64 = 0;
        while !b.at_end() {
            // Every output starts with nine fixed bytes: an 8-byte value and a 1-byte script
            // length.
            if b.rest().len() < 9 {
                return None;
            }
            let v = b.u64("output value").ok()?;
            if total.saturating_add(v) > value {
                break;
            }
            let slen = b.u8("script length").ok()? as usize;
            if !(MIN_OUTPUT_SCRIPT..=MAX_OUTPUT_SCRIPT).contains(&slen) {
                return None;
            }
            let script = b.take(slen, "output script").ok()?.to_vec();
            if skip(&script) {
                continue;
            }
            total += v;
            outputs.push(CoinbaseOutput { value: v, script });
            if outputs.len() >= MAX_COINBASER_OUTPUTS {
                break;
            }
        }
        Some(CoinbaserResponse { value, coinbaser_id, outputs })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareVerdict {
    Accepted,
    AcceptedTentatively,
    Rejected(RejectReason),
    /// Rejected with a reason code this build does not name.
    RejectedUnknown(u16),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum RejectReason {
    BadJobId = 10,
    BadCoinbaseId = 11,
    BadExtranonceSize = 12,
    BadTarget = 13,
    BadUsername = 14,
    BadCoinbaserId = 15,
    BadMerkleCount = 16,
    CoinbaseTooLarge = 17,
    CoinbaseMissing = 18,
    TargetMismatch = 19,
    HashNotZero = 20,
    HighHash = 21,
    CoinbaseIdMismatch = 22,
    BadNtime = 23,
    BadVersion = 24,
    StaleBlock = 25,
    BadCoinbase = 26,
    BadCoinbaseOutputs = 27,
    MissingPoolTag = 28,
    DuplicateWork = 29,
    Other = 30,
    // 40..43 are RATUM's own codes for the header v2 checks; the gateway defines only 10..30 and
    // logs an unknown code as an integer.
    /// The 0x03 section is absent (the upstream SHA256d share format, which this pool does
    /// not verify), its algorithm byte is not 0x01, or its time marker is not 0x04.
    BadBlake2bSection = 40,
    /// Reserved; not returned by this version.
    HeaderFieldMismatch = 41,
    /// Reserved; not returned by this version.
    HeaderMerkleMismatch = 42,
    MissingHeadline = 43,
}

impl RejectReason {
    pub fn from_code(code: u16) -> Option<Self> {
        Some(match code {
            10 => RejectReason::BadJobId,
            11 => RejectReason::BadCoinbaseId,
            12 => RejectReason::BadExtranonceSize,
            13 => RejectReason::BadTarget,
            14 => RejectReason::BadUsername,
            15 => RejectReason::BadCoinbaserId,
            16 => RejectReason::BadMerkleCount,
            17 => RejectReason::CoinbaseTooLarge,
            18 => RejectReason::CoinbaseMissing,
            19 => RejectReason::TargetMismatch,
            20 => RejectReason::HashNotZero,
            21 => RejectReason::HighHash,
            22 => RejectReason::CoinbaseIdMismatch,
            23 => RejectReason::BadNtime,
            24 => RejectReason::BadVersion,
            25 => RejectReason::StaleBlock,
            26 => RejectReason::BadCoinbase,
            27 => RejectReason::BadCoinbaseOutputs,
            28 => RejectReason::MissingPoolTag,
            29 => RejectReason::DuplicateWork,
            30 => RejectReason::Other,
            40 => RejectReason::BadBlake2bSection,
            41 => RejectReason::HeaderFieldMismatch,
            42 => RejectReason::HeaderMerkleMismatch,
            43 => RejectReason::MissingHeadline,
            _ => return None,
        })
    }
}

pub mod share_status {
    pub const ACCEPTED: u8 = 0x50;
    pub const ACCEPTED_TENTATIVELY: u8 = 0x55;
    pub const REJECTED: u8 = 0x66;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShareResponse {
    pub verdict: ShareVerdict,
    pub nonce: u32,
    /// The share's difficulty exponent (the gateway's `target_byte`, logged as "TargetPOT"), echoed
    /// from the submit; 0xFF when unknown.
    pub target_byte: u8,
    pub job_id: u8,
}

impl ShareResponse {
    pub fn encode(&self) -> Vec<u8> {
        let (status, reason) = match self.verdict {
            ShareVerdict::Accepted => (share_status::ACCEPTED, 0u16),
            ShareVerdict::AcceptedTentatively => (share_status::ACCEPTED_TENTATIVELY, 0),
            ShareVerdict::Rejected(r) => (share_status::REJECTED, r as u16),
            ShareVerdict::RejectedUnknown(code) => (share_status::REJECTED, code),
        };
        let mut out = Vec::with_capacity(10);
        out.push(server_subcmd::SHARE_RESPONSE);
        out.push(status);
        out.extend_from_slice(&reason.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.push(self.target_byte);
        out.push(self.job_id);
        out
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut c = Cursor::new(data);
        c.skip_if(server_subcmd::SHARE_RESPONSE);
        let status = c.u8("status").ok()?;
        let reason = c.u16("reason").ok()?;
        let verdict = match status {
            share_status::ACCEPTED => ShareVerdict::Accepted,
            share_status::ACCEPTED_TENTATIVELY => ShareVerdict::AcceptedTentatively,
            share_status::REJECTED => match RejectReason::from_code(reason) {
                Some(r) => ShareVerdict::Rejected(r),
                None => ShareVerdict::RejectedUnknown(reason),
            },
            _ => return None,
        };
        Some(ShareResponse {
            verdict,
            nonce: c.u32("nonce").ok()?,
            target_byte: c.u8("target byte").ok()?,
            job_id: c.u8("job id").ok()?,
        })
    }
}

pub fn blocknotify() -> Vec<u8> {
    vec![server_subcmd::BLOCKNOTIFY]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ClientConfig {
        ClientConfig {
            payout_script: {
                let mut s = vec![0x00, 0x14];
                s.extend_from_slice(&[0xab; 20]);
                s
            },
            prime_id: 0xdead_beef,
            coinbase_tag: "RATUM".to_string(),
            min_difficulty: 16384,
        }
    }

    #[test]
    fn config_roundtrips() {
        let c = sample();
        let bytes = c.encode().unwrap();
        assert_eq!(bytes[0], server_subcmd::CONFIG);
        assert_eq!(bytes[1], CONFIG_VERSION);
        assert_eq!(ClientConfig::decode(&bytes).unwrap(), c);
        assert_eq!(ClientConfig::decode(&bytes[1..]).unwrap(), c);
    }

    #[test]
    fn config_layout_is_exact() {
        let bytes = sample().encode().unwrap();
        assert_eq!(bytes.len(), 1 + 1 + 1 + 22 + 4 + 1 + 5 + 8 + 2);
        assert_eq!(bytes[2], 22);
        assert_eq!(&bytes[3..5], &[0x00, 0x14]);
        assert_eq!(&bytes[25..29], &0xdead_beefu32.to_le_bytes());
        assert_eq!(bytes[29], 5);
        assert_eq!(&bytes[30..35], b"RATUM");
        assert_eq!(&bytes[35..43], &16384u64.to_le_bytes());
        assert_eq!(&bytes[43..45], &[0x00, STRUCT_END]);
    }

    #[test]
    fn rejects_non_power_of_two_difficulty() {
        let mut c = sample();
        c.min_difficulty = 3000;
        assert_eq!(c.encode(), Err(Error::MinDiffNotPowerOfTwo(3000)));
    }

    #[test]
    fn rejects_oversized_fields() {
        let mut c = sample();
        c.payout_script = vec![0; 256];
        assert!(matches!(c.encode(), Err(Error::TooLong { field: "payout script", .. })));

        let mut c = sample();
        c.coinbase_tag = "x".repeat(255);
        assert!(matches!(c.encode(), Err(Error::TooLong { field: "coinbase tag", .. })));
    }

    #[test]
    fn decode_rejects_bad_terminator_and_version() {
        let mut bytes = sample().encode().unwrap();
        let n = bytes.len();
        bytes[n - 1] = 0xFF;
        assert!(ClientConfig::decode(&bytes).is_none());

        let mut bytes = sample().encode().unwrap();
        bytes[1] = 2;
        assert!(ClientConfig::decode(&bytes).is_none());
    }

    use crate::fixtures::p2wpkh;

    #[test]
    fn coinbaser_request_roundtrips() {
        let req = CoinbaserRequest { value: 312_500_000, prev_hash: [0x5a; 32] };
        let bytes = req.encode();
        assert_eq!(bytes.len(), 42);
        assert_eq!(bytes[0], client_subcmd::COINBASER_REQUEST);
        assert_eq!(CoinbaserRequest::decode(&bytes).unwrap(), req);
        let mut padded = bytes.clone();
        padded.extend_from_slice(&[0x77; 33]);
        assert_eq!(CoinbaserRequest::decode(&padded).unwrap(), req);
    }

    #[test]
    fn coinbaser_response_roundtrips() {
        let r = CoinbaserResponse {
            value: 312_500_000,
            coinbaser_id: 9,
            outputs: vec![
                CoinbaseOutput { value: 200_000_000, script: p2wpkh(0x01) },
                CoinbaseOutput { value: 100_000_000, script: p2wpkh(0x02) },
            ],
        };
        let bytes = r.encode().unwrap();
        assert_eq!(bytes[0], server_subcmd::COINBASER);
        assert_eq!(&bytes[1..9], &312_500_000u64.to_le_bytes());
        assert_eq!(u32::from_le_bytes(bytes[9..13].try_into().unwrap()), 1 + 2 * 31);
        assert_eq!(CoinbaserResponse::decode(&bytes).unwrap(), r);
    }

    #[test]
    fn coinbaser_rejects_overspend_and_bad_scripts() {
        let over = CoinbaserResponse {
            value: 100,
            coinbaser_id: 0,
            outputs: vec![CoinbaseOutput { value: 101, script: p2wpkh(0) }],
        };
        assert_eq!(over.encode(), Err(Error::SplitExceedsValue { total: 101, value: 100 }));

        let short_script = CoinbaserResponse {
            value: 100,
            coinbaser_id: 0,
            outputs: vec![CoinbaseOutput { value: 10, script: vec![0x51] }],
        };
        assert!(matches!(
            short_script.encode(),
            Err(Error::OutOfRange { field: "output script", .. })
        ));

        let long_script = CoinbaserResponse {
            value: 100,
            coinbaser_id: 0,
            outputs: vec![CoinbaseOutput { value: 10, script: vec![0x51; 65] }],
        };
        assert!(matches!(
            long_script.encode(),
            Err(Error::OutOfRange { field: "output script", .. })
        ));
    }

    #[test]
    fn retain_payable_removes_zero_value_outputs_bad_script_lengths_and_the_overflow() {
        let mut r = CoinbaserResponse {
            value: 1_000_000,
            coinbaser_id: 0,
            outputs: vec![
                CoinbaseOutput { value: 100, script: p2wpkh(0x01) },
                CoinbaseOutput { value: 100, script: vec![0x51] },
                CoinbaseOutput { value: 100, script: vec![0x51; 65] },
                CoinbaseOutput { value: 0, script: p2wpkh(0x02) },
                CoinbaseOutput { value: 100, script: vec![0x51; 64] },
                CoinbaseOutput { value: 100, script: vec![0x51, 0x52] },
            ],
        };
        assert_eq!(r.retain_payable(), 3);
        assert_eq!(r.outputs.len(), 3);
        assert!(r.encode().is_ok());

        let mut valid = CoinbaserResponse {
            value: 1_000,
            coinbaser_id: 0,
            outputs: vec![CoinbaseOutput { value: 10, script: p2wpkh(0) }],
        };
        assert_eq!(valid.retain_payable(), 0);
    }

    #[test]
    fn retain_payable_caps_the_output_count() {
        let mut r = CoinbaserResponse {
            value: u64::MAX,
            coinbaser_id: 0,
            outputs: (0..MAX_COINBASER_OUTPUTS + 10)
                .map(|i| CoinbaseOutput { value: 1, script: p2wpkh(i as u8) })
                .collect(),
        };
        assert_eq!(r.retain_payable(), 10);
        assert_eq!(r.outputs.len(), MAX_COINBASER_OUTPUTS);
    }

    #[test]
    fn coinbaser_empty_split_roundtrips() {
        // The gateway logs a 1-byte blob as "Coinbaser length is invalid (too short)", builds
        // its default coinbase and leaves its coinbaser id unassigned; this tests only RATUM's
        // encoder and decoder.
        let r = CoinbaserResponse { value: 312_500_000, coinbaser_id: 3, outputs: vec![] };
        let bytes = r.encode().unwrap();
        assert_eq!(u32::from_le_bytes(bytes[9..13].try_into().unwrap()), 1);
        assert_eq!(CoinbaserResponse::decode(&bytes).unwrap(), r);
    }

    #[test]
    fn share_response_roundtrips_every_verdict() {
        let base = ShareResponse {
            verdict: ShareVerdict::Accepted,
            nonce: 0x0bad_c0de,
            target_byte: 33,
            job_id: 200,
        };
        let mut verdicts = vec![ShareVerdict::Accepted, ShareVerdict::AcceptedTentatively];
        for code in 0..=60u16 {
            if let Some(r) = RejectReason::from_code(code) {
                assert_eq!(r as u16, code, "reason code {code} maps back to itself");
                verdicts.push(ShareVerdict::Rejected(r));
            }
        }
        assert_eq!(verdicts.len(), 2 + 25, "every reject reason is covered");
        for verdict in verdicts {
            let r = ShareResponse { verdict, ..base };
            assert_eq!(ShareResponse::decode(&r.encode()), Some(r), "{verdict:?}");
            assert_eq!(ShareResponse::decode(&r.encode()[1..]), Some(r), "{verdict:?} unprefixed");
        }

        assert_eq!(ShareResponse::decode(&[]), None);
        assert_eq!(ShareResponse::decode(&base.encode()[..5]), None);
        let mut unknown_status = base.encode();
        unknown_status[1] = 0x11;
        assert_eq!(ShareResponse::decode(&unknown_status), None);
        let mut unknown_reason =
            ShareResponse { verdict: ShareVerdict::Rejected(RejectReason::HighHash), ..base }
                .encode();
        unknown_reason[2] = 0xfe;
        // A reason this build does not name is still a rejection, and counted as one.
        let decoded = ShareResponse::decode(&unknown_reason).unwrap();
        assert_eq!(decoded.verdict, ShareVerdict::RejectedUnknown(0xfe));
        assert_eq!(ShareResponse::decode(&decoded.encode()), Some(decoded));
    }

    #[test]
    fn share_response_layout() {
        let ok = ShareResponse {
            verdict: ShareVerdict::Accepted,
            nonce: 0xdead_beef,
            target_byte: 14,
            job_id: 5,
        };
        let b = ok.encode();
        assert_eq!(b.len(), 10);
        assert_eq!(b[0], server_subcmd::SHARE_RESPONSE);
        assert_eq!(b[1], share_status::ACCEPTED);
        assert_eq!(&b[2..4], &0u16.to_le_bytes());
        assert_eq!(&b[4..8], &0xdead_beefu32.to_le_bytes());
        assert_eq!(b[8], 14);
        assert_eq!(b[9], 5);

        let bad = ShareResponse { verdict: ShareVerdict::Rejected(RejectReason::HighHash), ..ok };
        let b = bad.encode();
        assert_eq!(b[1], share_status::REJECTED);
        assert_eq!(u16::from_le_bytes(b[2..4].try_into().unwrap()), 21);

        let tentative = ShareResponse { verdict: ShareVerdict::AcceptedTentatively, ..ok };
        assert_eq!(tentative.encode()[1], share_status::ACCEPTED_TENTATIVELY);
    }
}
