use bytes::BufMut as _;

pub const POT_TARGET_PLACEHOLDER: u8 = 0xFF;

pub const TAG_SEPARATOR: u8 = 0x0F;
pub const TAG_END: u8 = 0x00;

pub const UID_PUSH_PREFIX_SIZE: usize = 1 + 2;
pub const UID_PUSH_SIZE_NO_PRIME: usize = UID_PUSH_PREFIX_SIZE;
pub const UID_PUSH_SIZE_V1: usize = UID_PUSH_PREFIX_SIZE + size_of::<u32>();
pub const UID_PUSH_SIZE_V3: usize = UID_PUSH_PREFIX_SIZE + size_of::<u64>();

pub const ENPREFIX_SIZE: usize = 2;
pub const EXTRANONCE_PUSH_SIZE: usize = 1 + ENPREFIX_SIZE + super::share::EXTRANONCE_SIZE;
pub const TAG_MARKER_BYTES: usize = 2;

pub fn tag_push_data(primary: &[u8], secondary: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(primary.len() + secondary.len() + TAG_MARKER_BYTES);
    data.put_slice(primary);
    if !secondary.is_empty() {
        data.put_u8(TAG_SEPARATOR);
        data.put_slice(secondary);
    }
    data.put_u8(TAG_END);
    data
}

pub const UID_PUSH_POT_AT: usize = 1;

pub fn uid_push(unique_id: u16, prime_id: &[u8]) -> Vec<u8> {
    let len = UID_PUSH_PREFIX_SIZE + prime_id.len();
    debug_assert!(matches!(len, UID_PUSH_SIZE_NO_PRIME | UID_PUSH_SIZE_V1 | UID_PUSH_SIZE_V3));
    let mut push = Vec::with_capacity(1 + len);
    push.put_u8(len as u8);
    push.put_u8(POT_TARGET_PLACEHOLDER);
    push.put_u16_le(unique_id);
    push.put_slice(prime_id);
    push
}
