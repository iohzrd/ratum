use crate::cursor::Cursor;
use crate::datum::codes::wire_codes;

pub mod server_subcmd {
    pub const CONFIG: u8 = 0x99;
    pub const COINBASER: u8 = 0x11;
    pub const VALIDATION: u8 = 0x50;
    pub const SHARE_RESPONSE: u8 = 0x8F;
    pub const BLOCKNOTIFY: u8 = 0xF9;
    pub const MIGRATION: u8 = 0xA4;
}

pub mod client_subcmd {
    pub const COINBASER_REQUEST: u8 = 0x10;
    pub const SUBMIT_POW: u8 = 0x27;
    pub const VALIDATION: u8 = 0x50;
}

pub use super::framing::STRUCT_END;
pub const CONFIG_VERSION: u8 = 1;
const CONFIG_FIXED_LEN: usize = 4 + size_of::<u32>() + size_of::<u64>() + 2;
pub const MAX_PAYOUT_SCRIPT: usize = 83;
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

fn check_config_fields(
    payout_script: &[u8],
    coinbase_tag: &str,
    min_difficulty: u64,
) -> Result<(), Error> {
    if payout_script.len() > MAX_PAYOUT_SCRIPT {
        return Err(Error::TooLong { field: "payout script", len: payout_script.len() });
    }
    if coinbase_tag.len() > MAX_COINBASE_TAG {
        return Err(Error::TooLong { field: "coinbase tag", len: coinbase_tag.len() });
    }
    if !min_difficulty.is_power_of_two() {
        return Err(Error::MinDiffNotPowerOfTwo(min_difficulty));
    }
    Ok(())
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
        check_config_fields(&self.payout_script, &self.coinbase_tag, self.min_difficulty)?;
        let tag = self.coinbase_tag.as_bytes();
        let mut out = Vec::with_capacity(CONFIG_FIXED_LEN + self.payout_script.len() + tag.len());
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
        Some(Self { payout_script, prime_id, coinbase_tag, min_difficulty })
    }
}

pub const CONFIG_VERSION_V3: u8 = 3;
const CONFIG_V3_FIXED_LEN: usize =
    CONFIG_FIXED_LEN + (size_of::<u64>() - size_of::<u32>()) + RESUME_TOKEN_LEN;

pub const RESUME_TOKEN_LEN: usize = 40;
pub type ResumeToken = [u8; RESUME_TOKEN_LEN];
pub const DBF_MARKER: [u8; 4] = *b"DBF\x01";
pub const CONFIG_FLAG_ABW_DISABLED: u8 = 0x01;

const TOKEN_PRIME_ID_LEN: usize = size_of::<u64>();

pub fn new_resume_token(prime_id: u64) -> ResumeToken {
    let mut t = [0u8; RESUME_TOKEN_LEN];
    t[..TOKEN_PRIME_ID_LEN].copy_from_slice(&prime_id.to_le_bytes());
    crate::rand::fill(&mut t[TOKEN_PRIME_ID_LEN..]);
    t
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientConfigV3 {
    pub payout_script: Vec<u8>,
    pub prime_id: u64,
    pub resume_token: ResumeToken,
    pub coinbase_tag: String,
    pub min_difficulty: u64,
    pub bulk_framing: bool,
    pub abw_disabled: bool,
}

impl ClientConfigV3 {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        check_config_fields(&self.payout_script, &self.coinbase_tag, self.min_difficulty)?;
        let tag = self.coinbase_tag.as_bytes();
        let mut out = Vec::with_capacity(
            CONFIG_V3_FIXED_LEN + self.payout_script.len() + tag.len() + DBF_MARKER.len(),
        );
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
        if b > MAX_COINBASE_TAG {
            return None;
        }
        let coinbase_tag = String::from_utf8_lossy(c.take(b, "coinbase tag").ok()?).into_owned();
        let min_difficulty = c.u64("min difficulty").ok()?;
        let flags = c.u8("flags").ok()?;
        if flags & !CONFIG_FLAG_ABW_DISABLED != 0 || c.u8("terminator").ok()? != STRUCT_END {
            return None;
        }
        let bulk_framing = c.rest().get(..DBF_MARKER.len()) == Some(&DBF_MARKER[..]);
        Some(Self {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationRequest {
    pub target: Option<MigrationTarget>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationTarget {
    pub host: String,
    pub port: u16,
    pub pubkey: [u8; MIGRATION_PUBKEY_LEN],
}

pub const MIGRATION_REVISION: u8 = 0;
pub const MIGRATION_ACTION_REDIRECT: u8 = 0;
pub const MIGRATION_ACTION_RETURN_HOME: u8 = 1;
pub const MAX_MIGRATION_HOST: usize = 1024;
pub const MIGRATION_PUBKEY_LEN: usize = 2 * 32;

impl MigrationRequest {
    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut c = Cursor::new(data);
        c.skip_if(server_subcmd::MIGRATION);
        if c.u8("revision").ok()? != MIGRATION_REVISION {
            return None;
        }
        match c.u8("action").ok()? {
            MIGRATION_ACTION_RETURN_HOME => {
                if c.u8("terminator").ok()? != STRUCT_END || !c.at_end() {
                    return None;
                }
                Some(Self { target: None })
            }
            MIGRATION_ACTION_REDIRECT => {
                let host_len = c.u16("host length").ok()? as usize;
                if host_len == 0 || host_len >= MAX_MIGRATION_HOST {
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
                let pubkey: [u8; MIGRATION_PUBKEY_LEN] = c.arr("pubkey").ok()?;
                if c.u8("terminator").ok()? != STRUCT_END || !c.at_end() {
                    return None;
                }
                Some(Self { target: Some(MigrationTarget { host, port, pubkey }) })
            }
            _ => None,
        }
    }
}

pub const MAX_COINBASER_BLOB: usize = 32767;
pub const MIN_OUTPUT_SCRIPT: usize = 2;
pub const MAX_OUTPUT_SCRIPT: usize = 64;
pub const MAX_COINBASER_OUTPUTS: usize = 512;
const COINBASER_OUTPUT_FIXED_LEN: usize = size_of::<u64>() + 1;
const COINBASER_RESPONSE_HEADER_LEN: usize = 1 + size_of::<u64>() + size_of::<u32>();
const COINBASER_REQUEST_LEN: usize = 1 + size_of::<u64>() + crate::bitcoin::HASH_SIZE + 1;

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
        Some(Self { value, prev_hash })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(COINBASER_REQUEST_LEN);
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
        let blob_len: usize =
            self.outputs.iter().map(|o| COINBASER_OUTPUT_FIXED_LEN + o.script.len()).sum();
        let mut blob = Vec::with_capacity(1 + blob_len);
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

        let mut out = Vec::with_capacity(COINBASER_RESPONSE_HEADER_LEN + blob.len());
        out.push(server_subcmd::COINBASER);
        out.extend_from_slice(&self.value.to_le_bytes());
        out.extend_from_slice(&(blob.len() as u32).to_le_bytes());
        out.extend_from_slice(&blob);
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
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
            let v = b.u64("output value").ok()?;
            if total.saturating_add(v) > value {
                break;
            }
            let slen = b.u8("script length").ok()? as usize;
            if !(MIN_OUTPUT_SCRIPT..=MAX_OUTPUT_SCRIPT).contains(&slen) {
                return None;
            }
            let script = b.take(slen, "output script").ok()?.to_vec();
            total += v;
            outputs.push(CoinbaseOutput { value: v, script });
            if outputs.len() >= MAX_COINBASER_OUTPUTS {
                break;
            }
        }
        Some(Self { value, coinbaser_id, outputs })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareVerdict {
    Accepted,
    AcceptedTentatively,
    Rejected(RejectReason),
    RejectedUnknown(u16),
}

wire_codes! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum RejectReason: u16 {
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
        BadBlake2bSection = 40,
        HeaderFieldMismatch = 41,
        HeaderMerkleMismatch = 42,
        NoSplit = 43,
        BadAbwSlot = 44,
    }
}

pub mod share_status {
    pub const ACCEPTED: u8 = 0x50;
    pub const ACCEPTED_TENTATIVELY: u8 = 0x55;
    pub const REJECTED: u8 = 0x66;
}

pub const SHARE_RESPONSE_ABW_MARKER: u8 = 0x06;

const SHARE_RESPONSE_LEN: usize = 1 + 1 + size_of::<u16>() + size_of::<u32>() + 1 + 1;
/// The raw proof-of-work hash and the 0xFE that closes the reference.
const ABW_REF_TAIL_LEN: usize = crate::bitcoin::HASH_SIZE + 1;
const SHARE_RESPONSE_ABW_LEN: usize = SHARE_RESPONSE_LEN + 2 + ABW_REF_TAIL_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AbwShareRef {
    pub slot: u8,
    pub raw_pow_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShareResponse {
    pub verdict: ShareVerdict,
    pub nonce: u32,
    pub target_byte: u8,
    pub job_id: u8,
    pub abw_ref: Option<AbwShareRef>,
}

impl ShareResponse {
    pub fn encode(&self) -> Vec<u8> {
        let (status, reason) = match self.verdict {
            ShareVerdict::Accepted => (share_status::ACCEPTED, 0u16),
            ShareVerdict::AcceptedTentatively => (share_status::ACCEPTED_TENTATIVELY, 0),
            ShareVerdict::Rejected(r) => (share_status::REJECTED, r.code()),
            ShareVerdict::RejectedUnknown(code) => (share_status::REJECTED, code),
        };
        let mut out = Vec::with_capacity(if self.abw_ref.is_some() {
            SHARE_RESPONSE_ABW_LEN
        } else {
            SHARE_RESPONSE_LEN
        });
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
        let abw_ref = match c.rest() {
            [SHARE_RESPONSE_ABW_MARKER, slot, tail @ ..]
                if tail.len() == ABW_REF_TAIL_LEN && *slot < super::abw::ASSIGNMENT_SLOTS =>
            {
                let (hash, end) = tail.split_at(crate::bitcoin::HASH_SIZE);
                (end == [STRUCT_END]).then(|| AbwShareRef {
                    slot: *slot,
                    raw_pow_hash: hash.try_into().expect("HASH_SIZE bytes"),
                })
            }
            _ => None,
        };
        Some(Self { verdict, nonce, target_byte, job_id, abw_ref })
    }
}

pub fn blocknotify() -> Vec<u8> {
    vec![server_subcmd::BLOCKNOTIFY]
}
