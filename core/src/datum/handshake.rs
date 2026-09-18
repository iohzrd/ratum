//! The DRS extension a version 3 hello carries: the protocol version the gateway asks for and the
//! resume token naming the session it continues.

pub(crate) const DRS_MARKER: [u8; 4] = *b"DRS\x01";
pub(crate) const DRS_RESUME_PRESENT: u8 = 1;
pub(crate) const DRS_FLAG_AT: usize = DRS_MARKER.len();
pub(crate) const DRS_TOKEN_AT: usize = DRS_FLAG_AT + 1;

pub const RESUME_TOKEN_LEN: usize = 40;
pub type ResumeToken = [u8; RESUME_TOKEN_LEN];
const TOKEN_PRIME_ID_LEN: usize = size_of::<u64>();

pub fn new_resume_token(prime_id: u64) -> ResumeToken {
    let mut t = [0u8; RESUME_TOKEN_LEN];
    let (id, rest) = t.split_at_mut(TOKEN_PRIME_ID_LEN);
    id.copy_from_slice(&prime_id.to_le_bytes());
    crate::rand::fill(rest);
    t
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolVersion {
    V1,
    V3 { resume: Option<ResumeToken> },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_resume_token_carries_the_prime_id_and_is_random() {
        let a = new_resume_token(0x0102_0304_0506_0708);
        let b = new_resume_token(0x0102_0304_0506_0708);
        assert_eq!(a[..8], 0x0102_0304_0506_0708u64.to_le_bytes());
        assert_ne!(a[..8], 1u64.to_le_bytes());
        assert_eq!(a[..8], b[..8]);
        assert_ne!(a[8..], b[8..]);
    }
}
