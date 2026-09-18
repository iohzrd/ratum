//! The pool's configuration message (0x99): the payout script, prime id, coinbase tag and minimum
//! difficulty every gateway builds work under. The version 3 form adds the resume token, the bulk
//! framing marker and the anti-block-withholding flag; the version 1 form carries a 32-bit prime
//! id.

use super::STRUCT_END;
use super::{Error, open_message, read_terminator, server_subcmd};
use crate::datum::bulk::DBF_MARKER;
use crate::datum::handshake::{RESUME_TOKEN_LEN, ResumeToken};
use crate::reader::ByteReader;
use bytes::BufMut as _;

pub(crate) const CONFIG_VERSION: u8 = 1;
pub(crate) const CONFIG_VERSION_V3: u8 = 3;
pub(crate) const CONFIG_FLAG_ABW_DISABLED: u8 = 0x01;
const CONFIG_FIXED_LEN: usize = 4 + size_of::<u32>() + size_of::<u64>() + 2;
const CONFIG_V3_EXTRA_LEN: usize =
    (size_of::<u64>() - size_of::<u32>()) + RESUME_TOKEN_LEN + DBF_MARKER.len();
pub const MAX_PAYOUT_SCRIPT_LEN: usize = 83;
pub const MAX_COINBASE_TAG_LEN: usize = 81;

fn push_counted(out: &mut Vec<u8>, bytes: &[u8]) {
    out.put_u8(bytes.len() as u8);
    out.put_slice(bytes);
}

fn take_counted<'a>(
    c: &mut ByteReader<'a>,
    what: &'static str,
    max: usize,
) -> Result<&'a [u8], Error> {
    let len = usize::from(c.u8(what)?);
    if len > max {
        return Err(Error::TooLong { field: what, len });
    }
    Ok(c.take(len, what)?)
}

const COINBASE_TAG_HOLDS_NUL: &str =
    "coinbase tag holds a NUL byte, which a C gateway reads as the end of the tag";

/// The tag as a gateway pushes it: the bytes before the first NUL, since the C gateway copies
/// the field into a NUL-terminated string and every later use of it stops there. Bytes that are
/// not UTF-8 are refused rather than replaced: replacing each invalid byte with U+FFFD, three
/// bytes, would put other bytes in the coinbase than the pool sent, and could make an 81-byte
/// tag too long for the scriptSig, after which the gateway builds no work at all.
fn coinbase_tag(field: &[u8]) -> Result<String, Error> {
    let before_nul = field.split(|&b| b == 0).next().unwrap_or_default();
    String::from_utf8(before_nul.to_vec())
        .map_err(|_| Error::Malformed("coinbase tag is not UTF-8"))
}

/// What the version 3 configuration carries beyond the version 1 fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct V3Config {
    pub resume_token: ResumeToken,
    pub bulk_framing: bool,
    pub abw_disabled: bool,
}

/// The pool's configuration message (0x99). `v3` is present for the version 3 message and
/// absent for version 1, whose prime id is 32 bits wide on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientConfig {
    pub payout_script: Vec<u8>,
    pub prime_id: u64,
    pub coinbase_tag: String,
    pub min_difficulty: u64,
    pub v3: Option<V3Config>,
}

impl ClientConfig {
    fn check_fields(&self) -> Result<(), Error> {
        if self.payout_script.len() > MAX_PAYOUT_SCRIPT_LEN {
            return Err(Error::TooLong { field: "payout script", len: self.payout_script.len() });
        }
        if self.coinbase_tag.len() > MAX_COINBASE_TAG_LEN {
            return Err(Error::TooLong { field: "coinbase tag", len: self.coinbase_tag.len() });
        }
        if self.coinbase_tag.contains('\0') {
            return Err(Error::Malformed(COINBASE_TAG_HOLDS_NUL));
        }
        if !self.min_difficulty.is_power_of_two() {
            return Err(Error::MinDifficultyNotPowerOfTwo(self.min_difficulty));
        }
        if self.v3.is_none() && u32::try_from(self.prime_id).is_err() {
            return Err(Error::PrimeIdTooWide(self.prime_id));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.check_fields()?;
        let tag = self.coinbase_tag.as_bytes();
        let mut out = Vec::with_capacity(
            CONFIG_FIXED_LEN + CONFIG_V3_EXTRA_LEN + self.payout_script.len() + tag.len(),
        );
        out.put_u8(server_subcmd::CONFIG);
        match self.v3 {
            None => {
                out.put_u8(CONFIG_VERSION);
                push_counted(&mut out, &self.payout_script);
                out.put_u32_le(self.prime_id as u32);
                push_counted(&mut out, tag);
                out.put_u64_le(self.min_difficulty);
                out.put_u8(0);
                out.put_u8(STRUCT_END);
            }
            Some(v3) => {
                out.put_u8(CONFIG_VERSION_V3);
                push_counted(&mut out, &self.payout_script);
                out.put_u64_le(self.prime_id);
                out.put_slice(&v3.resume_token);
                push_counted(&mut out, tag);
                out.put_u64_le(self.min_difficulty);
                out.put_u8(if v3.abw_disabled { CONFIG_FLAG_ABW_DISABLED } else { 0 });
                out.put_u8(STRUCT_END);
                if v3.bulk_framing {
                    out.put_slice(&DBF_MARKER);
                }
            }
        }
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut c = open_message(data, server_subcmd::CONFIG)?;
        let version = c.u8("version")?;
        let payout_script = take_counted(&mut c, "payout script", MAX_PAYOUT_SCRIPT_LEN)?.to_vec();
        let (prime_id, resume_token) = match version {
            CONFIG_VERSION => (u64::from(c.u32("prime id")?), None),
            CONFIG_VERSION_V3 => {
                (c.u64("prime id")?, Some(c.arr::<RESUME_TOKEN_LEN>("resume token")?))
            }
            other => return Err(Error::BadVersion(other)),
        };
        let coinbase_tag =
            coinbase_tag(take_counted(&mut c, "coinbase tag", MAX_COINBASE_TAG_LEN)?)?;
        let min_difficulty = c.u64("min difficulty")?;
        let flags = c.u8("flags")?;
        read_terminator(&mut c)?;
        let known_flags = if resume_token.is_some() { CONFIG_FLAG_ABW_DISABLED } else { 0 };
        if flags & !known_flags != 0 {
            return Err(Error::BadFlags(flags));
        }
        let v3 = resume_token.map(|resume_token| V3Config {
            resume_token,
            bulk_framing: c.rest().get(..DBF_MARKER.len()) == Some(&DBF_MARKER[..]),
            abw_disabled: flags & CONFIG_FLAG_ABW_DISABLED != 0,
        });
        Ok(Self { payout_script, prime_id, coinbase_tag, min_difficulty, v3 })
    }
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
            v3: None,
        }
    }

    fn sample_v3() -> ClientConfig {
        ClientConfig {
            payout_script: vec![0x51],
            prime_id: 0x1122_3344_5566_7788,
            coinbase_tag: "RATUM".into(),
            min_difficulty: 1024,
            v3: Some(V3Config {
                resume_token: [7u8; RESUME_TOKEN_LEN],
                bulk_framing: true,
                abw_disabled: false,
            }),
        }
    }

    #[test]
    fn config_roundtrips() {
        for c in [sample(), sample_v3()] {
            let bytes = c.encode().unwrap();
            assert_eq!(bytes[0], server_subcmd::CONFIG);
            assert_eq!(bytes[1], if c.v3.is_some() { CONFIG_VERSION_V3 } else { CONFIG_VERSION });
            assert_eq!(ClientConfig::decode(&bytes).unwrap(), c);
            assert_eq!(
                ClientConfig::decode(&bytes[1..]),
                Err(Error::WrongMessage { want: server_subcmd::CONFIG, got: bytes[1] }),
                "the subcommand is required"
            );
        }
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
        assert_eq!(c.encode(), Err(Error::MinDifficultyNotPowerOfTwo(3000)));
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
    fn a_version_1_config_carries_a_32_bit_prime_id() {
        let mut c = sample();
        c.prime_id = 0x1_0000_0000;
        assert_eq!(c.encode(), Err(Error::PrimeIdTooWide(0x1_0000_0000)));
        c.v3 = sample_v3().v3;
        assert_eq!(ClientConfig::decode(&c.encode().unwrap()).unwrap().prime_id, 0x1_0000_0000);
    }

    #[test]
    fn decode_rejects_bad_terminator_and_version() {
        let mut bytes = sample().encode().unwrap();
        let n = bytes.len();
        bytes[n - 1] = 0xFF;
        assert_eq!(ClientConfig::decode(&bytes), Err(Error::BadTerminator));

        let mut bytes = sample().encode().unwrap();
        bytes[1] = 2;
        assert_eq!(ClientConfig::decode(&bytes), Err(Error::BadVersion(2)));

        let mut bytes = sample().encode().unwrap();
        bytes[n - 2] = CONFIG_FLAG_ABW_DISABLED;
        assert_eq!(
            ClientConfig::decode(&bytes),
            Err(Error::BadFlags(CONFIG_FLAG_ABW_DISABLED)),
            "version 1 carries no flags"
        );
    }

    #[test]
    fn v3_config_flags_byte_carries_the_abw_policy_and_rejects_unknown_bits() {
        let base = sample_v3();
        let on = base.encode().unwrap();
        let fe = on.len() - 1 - DBF_MARKER.len();
        assert_eq!(on[fe], STRUCT_END);
        assert_eq!(on[fe - 1], 0);
        assert_eq!(ClientConfig::decode(&on).unwrap(), base);

        let off = ClientConfig {
            v3: Some(V3Config { abw_disabled: true, ..base.v3.unwrap() }),
            ..base.clone()
        };
        let bytes = off.encode().unwrap();
        assert_eq!(bytes[fe - 1], CONFIG_FLAG_ABW_DISABLED);
        assert_eq!(ClientConfig::decode(&bytes).unwrap(), off);

        let unframed = ClientConfig {
            v3: Some(V3Config { bulk_framing: false, ..base.v3.unwrap() }),
            ..base.clone()
        };
        let bytes = unframed.encode().unwrap();
        assert_eq!(bytes.len(), on.len() - DBF_MARKER.len());
        assert_eq!(ClientConfig::decode(&bytes).unwrap(), unframed);

        let mut bad = on.clone();
        bad[fe - 1] = 0x80;
        assert_eq!(ClientConfig::decode(&bad), Err(Error::BadFlags(0x80)));
        let mut bad = on;
        bad[fe - 1] = CONFIG_FLAG_ABW_DISABLED | 0x02;
        assert_eq!(
            ClientConfig::decode(&bad),
            Err(Error::BadFlags(CONFIG_FLAG_ABW_DISABLED | 0x02))
        );
    }

    /// The tag field of `c` replaced by `tag`, with its count byte.
    fn with_tag_bytes(c: &ClientConfig, tag: &[u8]) -> Vec<u8> {
        let placeholder = ClientConfig { coinbase_tag: "\u{1}".into(), ..c.clone() };
        let bytes = placeholder.encode().unwrap();
        let at = bytes.windows(2).position(|w| w == [1, 1]).expect("count 1, byte 0x01");
        let mut out = bytes[..at].to_vec();
        out.push(tag.len() as u8);
        out.extend_from_slice(tag);
        out.extend_from_slice(&bytes[at + 2..]);
        out
    }

    #[test]
    fn the_coinbase_tag_ends_at_its_first_nul_as_the_c_gateway_reads_it() {
        for c in [sample(), sample_v3()] {
            let decoded = ClientConfig::decode(&with_tag_bytes(&c, b"OCEAN\0hidden")).unwrap();
            assert_eq!(decoded.coinbase_tag, "OCEAN");
            let decoded = ClientConfig::decode(&with_tag_bytes(&c, b"\0OCEAN")).unwrap();
            assert_eq!(decoded.coinbase_tag, "", "a leading NUL is an empty tag");
            assert_eq!(ClientConfig::decode(&with_tag_bytes(&c, b"RATUM")).unwrap(), c);
        }
        let with_nul = ClientConfig { coinbase_tag: "A\0B".into(), ..sample() };
        assert_eq!(with_nul.encode(), Err(Error::Malformed(COINBASE_TAG_HOLDS_NUL)));
    }

    #[test]
    fn a_coinbase_tag_that_is_not_utf8_is_refused_rather_than_replaced() {
        let invalid = [0xffu8; MAX_COINBASE_TAG_LEN];
        for c in [sample(), sample_v3()] {
            assert_eq!(
                ClientConfig::decode(&with_tag_bytes(&c, &invalid)),
                Err(Error::Malformed("coinbase tag is not UTF-8"))
            );
            assert_eq!(
                ClientConfig::decode(&with_tag_bytes(&c, b"ok\0\xff")).unwrap().coinbase_tag,
                "ok",
                "bytes after the NUL are not read"
            );
            let multibyte = "\u{e9}".repeat(MAX_COINBASE_TAG_LEN / 2);
            let decoded = ClientConfig::decode(&with_tag_bytes(&c, multibyte.as_bytes())).unwrap();
            assert_eq!(decoded.coinbase_tag, multibyte, "UTF-8 is kept byte for byte");
        }
    }

    #[test]
    fn config_limits_match_what_a_convoy_gateway_accepts() {
        let mut c = ClientConfig {
            payout_script: vec![0x51],
            prime_id: 1,
            coinbase_tag: "t".repeat(81),
            min_difficulty: 1,
            v3: Some(V3Config {
                resume_token: [0u8; RESUME_TOKEN_LEN],
                bulk_framing: false,
                abw_disabled: false,
            }),
        };
        assert!(c.encode().is_ok(), "81-byte tag is the most a CONVOY gateway takes");
        c.coinbase_tag = "t".repeat(82);
        assert!(matches!(c.encode(), Err(Error::TooLong { field: "coinbase tag", .. })));
        c.coinbase_tag = "t".repeat(81);
        let mut bytes = c.encode().unwrap();
        let tag_len_at = 2 + 1 + 1 + 8 + RESUME_TOKEN_LEN;
        assert_eq!(bytes[tag_len_at], 81);
        bytes[tag_len_at] = 82;
        bytes.insert(tag_len_at + 1, b't');
        assert_eq!(
            ClientConfig::decode(&bytes),
            Err(Error::TooLong { field: "coinbase tag", len: 82 })
        );
        c.coinbase_tag = "t".into();
        c.payout_script = vec![0x51; 83];
        let bytes = c.encode().expect("83-byte payout script");
        assert_eq!(ClientConfig::decode(&bytes).unwrap().payout_script.len(), 83);
        c.payout_script = vec![0x51; 84];
        assert!(matches!(c.encode(), Err(Error::TooLong { field: "payout script", .. })));
        let v1 =
            ClientConfig { payout_script: vec![0x51], coinbase_tag: "t".repeat(82), v3: None, ..c };
        assert!(matches!(v1.encode(), Err(Error::TooLong { field: "coinbase tag", .. })));
    }
}
