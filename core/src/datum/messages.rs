use crate::cursor::Cursor;

/// The first payload byte of a `cmd::MINING` frame sent by the pool: the mining sub-command.
pub mod server_subcmd {
    pub const CONFIG: u8 = 0x99;
    pub const COINBASER: u8 = 0x11;
    pub const VALIDATION: u8 = 0x50;
    pub const SHARE_RESPONSE: u8 = 0x8F;
    pub const BLOCKNOTIFY: u8 = 0xF9;
    /// version 3 protocol: server-requested migration to another pool server. Must be signed.
    pub const MIGRATION: u8 = 0xA4;
    // 0xA5..=0xA9 are the anti-block-withholding subcommands; see `super::abw::subcmd`.
}

/// The first payload byte of a `cmd::MINING` frame sent by the gateway: the mining sub-command.
pub mod client_subcmd {
    pub const COINBASER_REQUEST: u8 = 0x10;
    pub const SUBMIT_POW: u8 = 0x27;
    pub const VALIDATION: u8 = 0x50;
}

pub use super::framing::STRUCT_END;
pub const CONFIG_VERSION: u8 = 1;
/// The pool's payout script in the configuration message. The C gateway's parser refuses a
/// longer one (`MAX_OUTPUT_SCRIPT_LEN`, 83, the RDTS output-script ceiling); the version 1
/// fork refuses one over 64 (its `pool_addr_script` field), and `ratum-prime` limits its
/// own to the 34-byte coinbase output ceiling. Coinbaser outputs are bounded separately by
/// `MAX_OUTPUT_SCRIPT`.
pub const MAX_PAYOUT_SCRIPT: usize = 83;
/// One less than the C gateway's `MAX_COINBASE_TAG_SPACE` (82): its configuration parser
/// rejects a tag of 82 bytes or more as one that can never fit the coinbase, and refuses the
/// whole configuration.
pub const MAX_COINBASE_TAG: usize = 81;

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

/// The version 3 protocol's configuration version. A version 3 gateway rejects versions 1 and 2, and
/// a v1 gateway rejects this, so the server picks the version from the hello's DRS
/// extension (present only in version 3 hellos).
pub const CONFIG_VERSION_V3: u8 = 3;
/// `DATUM_RESUME_TOKEN_SIZE`. Bytes 0..8 must be the prime ID little-endian: the gateway
/// treats a resume as accepted only when the configured prime ID equals that prefix and the
/// whole token echoes what it sent.
pub const RESUME_TOKEN_LEN: usize = 40;
pub type ResumeToken = [u8; RESUME_TOKEN_LEN];
/// Appended after the v3 config terminator to advertise bulk framing, and the marker of a
/// bulk fragment.
pub const DBF_MARKER: [u8; 4] = *b"DBF\x01";
/// The byte before the v3 terminator is a flags byte (`0x00` in v1, where it must be zero).
/// The only defined bit: the pool runs without anti-block-withholding, so the gateway uses the
/// null XOR key, omits the 0x05 slot section, and classifies and submits blocks itself. Any
/// other bit set makes the gateway reject the configuration.
pub const CONFIG_FLAG_ABW_DISABLED: u8 = 0x01;

/// Whether a resume token carries `prime_id` in its first eight bytes, the invariant the
/// gateway checks before treating a configuration as a resume.
pub fn token_matches_prime_id(token: &ResumeToken, prime_id: u64) -> bool {
    u64::from_le_bytes(token[..8].try_into().expect("eight bytes")) == prime_id
}

/// A token for one new session: `prime_id` little-endian, then 32 bytes from the CSPRNG.
/// Random, so a token names one session and a pool restart declines every resume.
pub fn new_resume_token(prime_id: u64) -> ResumeToken {
    let mut t = [0u8; RESUME_TOKEN_LEN];
    t[..8].copy_from_slice(&prime_id.to_le_bytes());
    dryoc::rng::copy_randombytes(&mut t[8..]);
    t
}

/// The version 3 client configuration (version 3): u64 prime ID, resume token, and an
/// optional trailing bulk-framing advertisement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientConfigV3 {
    pub payout_script: Vec<u8>,
    pub prime_id: u64,
    pub resume_token: ResumeToken,
    pub coinbase_tag: String,
    pub min_difficulty: u64,
    /// Advertise bulk framing (`DBF\x01` after the terminator). Re-evaluated by the gateway
    /// on every configuration message.
    pub bulk_framing: bool,
    /// `CONFIG_FLAG_ABW_DISABLED`: this pool does not run anti-block-withholding.
    pub abw_disabled: bool,
}

impl ClientConfigV3 {
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
        let mut out =
            Vec::with_capacity(64 + RESUME_TOKEN_LEN + self.payout_script.len() + tag.len());
        out.push(server_subcmd::CONFIG);
        out.push(CONFIG_VERSION_V3);
        out.push(self.payout_script.len() as u8);
        out.extend_from_slice(&self.payout_script);
        out.extend_from_slice(&self.prime_id.to_le_bytes());
        out.extend_from_slice(&self.resume_token);
        out.push(tag.len() as u8);
        out.extend_from_slice(tag);
        out.extend_from_slice(&self.min_difficulty.to_le_bytes());
        out.push(if self.abw_disabled { CONFIG_FLAG_ABW_DISABLED } else { 0 });
        out.push(STRUCT_END);
        if self.bulk_framing {
            out.extend_from_slice(&DBF_MARKER);
        }
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut c = Cursor::new(data);
        c.skip_if(server_subcmd::CONFIG);
        if c.u8("version").ok()? != CONFIG_VERSION_V3 {
            return None;
        }
        let a = c.u8("script length").ok()? as usize;
        if a > MAX_PAYOUT_SCRIPT {
            return None;
        }
        let payout_script = c.take(a, "payout script").ok()?.to_vec();
        let prime_id = c.u64("prime id").ok()?;
        let resume_token: ResumeToken = c.arr("resume token").ok()?;
        let b = c.u8("tag length").ok()? as usize;
        // The C gateway refuses the configuration for a tag of `MAX_COINBASE_TAG_SPACE` (82)
        // bytes or more.
        if b > MAX_COINBASE_TAG {
            return None;
        }
        let coinbase_tag = String::from_utf8_lossy(c.take(b, "coinbase tag").ok()?).into_owned();
        let min_difficulty = c.u64("min difficulty").ok()?;
        let flags = c.u8("flags").ok()?;
        if flags & !CONFIG_FLAG_ABW_DISABLED != 0 || c.u8("terminator").ok()? != STRUCT_END {
            return None;
        }
        // The gateway reads exactly four bytes after the terminator and ignores the rest.
        let bulk_framing = c.rest().get(..4) == Some(&DBF_MARKER[..]);
        Some(ClientConfigV3 {
            payout_script,
            prime_id,
            resume_token,
            coinbase_tag,
            min_difficulty,
            bulk_framing,
            abw_disabled: flags & CONFIG_FLAG_ABW_DISABLED != 0,
        })
    }
}

/// A migration request (subcommand 0xA4, signed): `Some(target)` redirects the gateway,
/// `None` returns it to its configured server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationRequest {
    pub target: Option<MigrationTarget>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationTarget {
    pub host: String,
    pub port: u16,
    /// 32 bytes ed25519 signing pubkey then 32 bytes x25519 box pubkey.
    pub pubkey: [u8; 64],
}

pub const MIGRATION_REVISION: u8 = 0;

impl MigrationRequest {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(72 + self.target.as_ref().map_or(0, |t| t.host.len()));
        out.push(server_subcmd::MIGRATION);
        out.push(MIGRATION_REVISION);
        match &self.target {
            None => {
                out.push(1);
            }
            Some(t) => {
                let host = t.host.as_bytes();
                if host.is_empty() || host.len() >= 1024 || host.contains(&0) {
                    return Err(Error::OutOfRange { field: "migration host", len: host.len() });
                }
                if t.port == 0 {
                    return Err(Error::OutOfRange { field: "migration port", len: 0 });
                }
                out.push(0);
                out.extend_from_slice(&(host.len() as u16).to_le_bytes());
                out.extend_from_slice(host);
                out.extend_from_slice(&t.port.to_le_bytes());
                out.extend_from_slice(&t.pubkey);
            }
        }
        out.push(STRUCT_END);
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut c = Cursor::new(data);
        c.skip_if(server_subcmd::MIGRATION);
        if c.u8("revision").ok()? != MIGRATION_REVISION {
            return None;
        }
        match c.u8("action").ok()? {
            1 => {
                if c.u8("terminator").ok()? != STRUCT_END || !c.at_end() {
                    return None;
                }
                Some(MigrationRequest { target: None })
            }
            0 => {
                let host_len = c.u16("host length").ok()? as usize;
                if host_len == 0 || host_len >= 1024 {
                    return None;
                }
                let host = c.take(host_len, "host").ok()?;
                if host.contains(&0) {
                    return None;
                }
                let host = String::from_utf8_lossy(host).into_owned();
                let port = c.u16("port").ok()?;
                if port == 0 {
                    return None;
                }
                let pubkey: [u8; 64] = c.arr("pubkey").ok()?;
                if c.u8("terminator").ok()? != STRUCT_END || !c.at_end() {
                    return None;
                }
                Some(MigrationRequest { target: Some(MigrationTarget { host, port, pubkey }) })
            }
            _ => None,
        }
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
    // 40..42 are RATUM's own codes for the header v2 checks; the gateway defines only 10..30 and
    // logs an unknown code as an integer.
    /// The 0x03 section is absent (the upstream SHA256d share format, which this pool does
    /// not verify), its algorithm byte is not 0x01, or its time marker is not 0x04.
    BadBlake2bSection = 40,
    /// Reserved; not returned by this version.
    HeaderFieldMismatch = 41,
    /// Reserved; not returned by this version.
    HeaderMerkleMismatch = 42,
    /// RATUM's own code: a version 3 session share names no ABW slot, an unseeded one, or one out
    /// of range.
    BadAbwSlot = 43,
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
            43 => RejectReason::BadAbwSlot,
            _ => return None,
        })
    }
}

pub mod share_status {
    pub const ACCEPTED: u8 = 0x50;
    pub const ACCEPTED_TENTATIVELY: u8 = 0x55;
    pub const REJECTED: u8 = 0x66;
}

/// The marker byte introducing a share response's exact ABW reference.
pub const SHARE_RESPONSE_ABW_MARKER: u8 = 0x06;

/// The version 3 protocol's exact share reference: the ABW slot (wire 0..15) and the raw
/// (unmasked) PoW hash. A version 3 gateway removes exactly one replay entry with it; without it
/// the gateway matches on the ambiguous (nonce, PoT, job) triple.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AbwShareRef {
    pub slot: u8,
    pub raw_pow_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShareResponse {
    pub verdict: ShareVerdict,
    pub nonce: u32,
    /// The share's difficulty exponent (the gateway's `target_byte`, logged as "TargetPOT"), echoed
    /// from the submit; 0xFF when unknown.
    pub target_byte: u8,
    pub job_id: u8,
    /// `None` on v1 sessions; the version 3 protocol appends the 0x06 exact reference.
    pub abw_ref: Option<AbwShareRef>,
}

impl ShareResponse {
    pub fn encode(&self) -> Vec<u8> {
        let (status, reason) = match self.verdict {
            ShareVerdict::Accepted => (share_status::ACCEPTED, 0u16),
            ShareVerdict::AcceptedTentatively => (share_status::ACCEPTED_TENTATIVELY, 0),
            ShareVerdict::Rejected(r) => (share_status::REJECTED, r as u16),
            ShareVerdict::RejectedUnknown(code) => (share_status::REJECTED, code),
        };
        let mut out = Vec::with_capacity(if self.abw_ref.is_some() { 45 } else { 10 });
        out.push(server_subcmd::SHARE_RESPONSE);
        out.push(status);
        out.extend_from_slice(&reason.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.push(self.target_byte);
        out.push(self.job_id);
        if let Some(r) = &self.abw_ref {
            out.push(SHARE_RESPONSE_ABW_MARKER);
            out.push(r.slot);
            out.extend_from_slice(&r.raw_pow_hash);
            out.push(STRUCT_END);
        }
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
        let nonce = c.u32("nonce").ok()?;
        let target_byte = c.u8("target byte").ok()?;
        let job_id = c.u8("job id").ok()?;
        // The C gateway accepts the reference only at exactly this length and shape;
        // anything else is treated as the legacy 9-byte body.
        let abw_ref = match c.rest() {
            [SHARE_RESPONSE_ABW_MARKER, slot, hash @ ..] if hash.len() == 33 && *slot < 16 => {
                (hash[32] == STRUCT_END).then(|| AbwShareRef {
                    slot: *slot,
                    raw_pow_hash: hash[..32].try_into().expect("32 bytes"),
                })
            }
            _ => None,
        };
        Some(ShareResponse { verdict, nonce, target_byte, job_id, abw_ref })
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
            abw_ref: None,
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
    fn v3_config_flags_byte_carries_the_abw_policy_and_rejects_unknown_bits() {
        let base = ClientConfigV3 {
            payout_script: vec![0x51],
            prime_id: 0x1122_3344_5566_7788,
            resume_token: [7u8; RESUME_TOKEN_LEN],
            coinbase_tag: "RATUM".into(),
            min_difficulty: 1024,
            bulk_framing: true,
            abw_disabled: false,
        };
        let on = base.encode().unwrap();
        // The byte before the 0xFE terminator is the flags byte: zero with ABW on.
        let fe = on.len() - 1 - DBF_MARKER.len();
        assert_eq!(on[fe], STRUCT_END);
        assert_eq!(on[fe - 1], 0);
        assert_eq!(ClientConfigV3::decode(&on).unwrap(), base);

        let off = ClientConfigV3 { abw_disabled: true, ..base.clone() };
        let bytes = off.encode().unwrap();
        assert_eq!(bytes[fe - 1], CONFIG_FLAG_ABW_DISABLED);
        assert_eq!(ClientConfigV3::decode(&bytes).unwrap(), off);

        // The C gateway rejects any other flag bit; so does this decoder.
        let mut bad = on.clone();
        bad[fe - 1] = 0x80;
        assert_eq!(ClientConfigV3::decode(&bad), None);
        let mut bad = on;
        bad[fe - 1] = CONFIG_FLAG_ABW_DISABLED | 0x02;
        assert_eq!(ClientConfigV3::decode(&bad), None);
    }

    #[test]
    fn a_new_resume_token_carries_the_prime_id_and_is_random() {
        let a = new_resume_token(0x0102_0304_0506_0708);
        let b = new_resume_token(0x0102_0304_0506_0708);
        assert!(token_matches_prime_id(&a, 0x0102_0304_0506_0708));
        assert!(!token_matches_prime_id(&a, 1));
        assert_eq!(a[..8], b[..8]);
        assert_ne!(a[8..], b[8..]);
    }

    #[test]
    fn config_limits_match_what_a_convoy_gateway_accepts() {
        // A tag of 82 bytes or more is refused by the C parser as one that can never fit.
        let mut c = ClientConfigV3 {
            payout_script: vec![0x51],
            prime_id: 1,
            resume_token: [0u8; RESUME_TOKEN_LEN],
            coinbase_tag: "t".repeat(81),
            min_difficulty: 1,
            bulk_framing: false,
            abw_disabled: false,
        };
        assert!(c.encode().is_ok(), "81-byte tag is the most a CONVOY gateway takes");
        c.coinbase_tag = "t".repeat(82);
        assert!(matches!(c.encode(), Err(Error::TooLong { field: "coinbase tag", .. })));
        // The decoder refuses what the C parser refuses: an 82-byte tag written by hand.
        c.coinbase_tag = "t".repeat(81);
        let mut bytes = c.encode().unwrap();
        let tag_len_at = 2 + 1 + 1 + 8 + RESUME_TOKEN_LEN;
        assert_eq!(bytes[tag_len_at], 81);
        bytes[tag_len_at] = 82;
        bytes.insert(tag_len_at + 1, b't');
        assert_eq!(ClientConfigV3::decode(&bytes), None);
        // The payout script field is capped at the C gateway's MAX_OUTPUT_SCRIPT_LEN, 83.
        c.coinbase_tag = "t".into();
        c.payout_script = vec![0x51; 83];
        let bytes = c.encode().expect("83-byte payout script");
        assert_eq!(ClientConfigV3::decode(&bytes).unwrap().payout_script.len(), 83);
        c.payout_script = vec![0x51; 84];
        assert!(matches!(c.encode(), Err(Error::TooLong { field: "payout script", .. })));
        // The v1 encoder shares the tag limit (the same C parser reads it).
        let v1 = ClientConfig {
            payout_script: vec![0x51],
            prime_id: 1,
            coinbase_tag: "t".repeat(82),
            min_difficulty: 1,
        };
        assert!(matches!(v1.encode(), Err(Error::TooLong { field: "coinbase tag", .. })));
    }

    #[test]
    fn share_response_layout() {
        let ok = ShareResponse {
            verdict: ShareVerdict::Accepted,
            nonce: 0xdead_beef,
            target_byte: 14,
            job_id: 5,
            abw_ref: None,
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
