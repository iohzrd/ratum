//! The pool's answer to a share (0x8F): accepted, accepted tentatively, or rejected with a reason
//! code, followed by the anti-block-withholding reference when the share was mined under an
//! assignment.

use super::abw::{ASSIGNMENT_SLOTS, CandidateRef};
use super::{Error, STRUCT_END, open_message, server_subcmd};
use crate::datum::codes::wire_codes;
use bytes::BufMut as _;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareVerdict {
    Accepted,
    AcceptedTentatively,
    Rejected(RejectReason),
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
    unknown Unknown;
}

pub(crate) mod share_status {
    pub(crate) const ACCEPTED: u8 = 0x50;
    pub(crate) const ACCEPTED_TENTATIVELY: u8 = 0x55;
    pub(crate) const REJECTED: u8 = 0x66;
}

pub(crate) const SHARE_RESPONSE_ABW_MARKER: u8 = 0x06;

const SHARE_RESPONSE_LEN: usize = 1 + 1 + size_of::<u16>() + size_of::<u32>() + 1 + 1;
const ABW_REF_TAIL_LEN: usize = crate::bitcoin::HASH_SIZE + 1;
const SHARE_RESPONSE_ABW_LEN: usize = SHARE_RESPONSE_LEN + 2 + ABW_REF_TAIL_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShareResponse {
    pub verdict: ShareVerdict,
    pub nonce: u32,
    pub target_byte: u8,
    pub job_id: u8,
    pub abw_ref: Option<CandidateRef>,
}

impl ShareResponse {
    pub fn encode(&self) -> Vec<u8> {
        let (status, reason) = match self.verdict {
            ShareVerdict::Accepted => (share_status::ACCEPTED, 0u16),
            ShareVerdict::AcceptedTentatively => (share_status::ACCEPTED_TENTATIVELY, 0),
            ShareVerdict::Rejected(r) => (share_status::REJECTED, r.code()),
        };
        let mut out = Vec::with_capacity(if self.abw_ref.is_some() {
            SHARE_RESPONSE_ABW_LEN
        } else {
            SHARE_RESPONSE_LEN
        });
        out.put_u8(server_subcmd::SHARE_RESPONSE);
        out.put_u8(status);
        out.put_u16_le(reason);
        out.put_u32_le(self.nonce);
        out.put_u8(self.target_byte);
        out.put_u8(self.job_id);
        if let Some(r) = &self.abw_ref {
            out.put_u8(SHARE_RESPONSE_ABW_MARKER);
            out.put_u8(r.slot);
            out.put_slice(&r.raw_pow_hash_le);
            out.put_u8(STRUCT_END);
        }
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut c = open_message(data, server_subcmd::SHARE_RESPONSE)?;
        let status = c.u8("status")?;
        let reason = c.u16("reason")?;
        let verdict = match status {
            share_status::ACCEPTED => ShareVerdict::Accepted,
            share_status::ACCEPTED_TENTATIVELY => ShareVerdict::AcceptedTentatively,
            share_status::REJECTED => ShareVerdict::Rejected(RejectReason::from_code(reason)),
            other => return Err(Error::BadStatus(other)),
        };
        let nonce = c.u32("nonce")?;
        let target_byte = c.u8("target byte")?;
        let job_id = c.u8("job id")?;
        let abw_ref = match c.rest() {
            [SHARE_RESPONSE_ABW_MARKER, slot, tail @ ..]
                if tail.len() == ABW_REF_TAIL_LEN && *slot < ASSIGNMENT_SLOTS =>
            {
                let (hash, end) = tail.split_at(crate::bitcoin::HASH_SIZE);
                (end == [STRUCT_END]).then(|| CandidateRef {
                    slot: *slot,
                    raw_pow_hash_le: hash.try_into().expect("HASH_SIZE bytes"),
                })
            }
            _ => None,
        };
        Ok(Self { verdict, nonce, target_byte, job_id, abw_ref })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            let r = RejectReason::from_code(code);
            if !matches!(r, RejectReason::Unknown(_)) {
                assert_eq!(r.code(), code, "reason code {code} maps back to itself");
                verdicts.push(ShareVerdict::Rejected(r));
            }
        }
        assert_eq!(verdicts.len(), 2 + 26, "every reject reason is covered");
        for verdict in verdicts {
            let r = ShareResponse { verdict, ..base };
            assert_eq!(ShareResponse::decode(&r.encode()), Ok(r), "{verdict:?}");
            assert!(
                matches!(ShareResponse::decode(&r.encode()[1..]), Err(Error::WrongMessage { .. })),
                "{verdict:?} without its subcommand"
            );
        }

        assert!(ShareResponse::decode(&[]).is_err());
        assert!(ShareResponse::decode(&base.encode()[..5]).is_err());
        let mut unknown_status = base.encode();
        unknown_status[1] = 0x11;
        assert_eq!(ShareResponse::decode(&unknown_status), Err(Error::BadStatus(0x11)));
        let mut unknown_reason =
            ShareResponse { verdict: ShareVerdict::Rejected(RejectReason::HighHash), ..base }
                .encode();
        unknown_reason[2] = 0xfe;
        let decoded = ShareResponse::decode(&unknown_reason).unwrap();
        assert_eq!(decoded.verdict, ShareVerdict::Rejected(RejectReason::Unknown(0xfe)));
        assert_eq!(ShareResponse::decode(&decoded.encode()), Ok(decoded));
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
