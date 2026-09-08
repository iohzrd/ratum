//! The identifying pushes the gateway writes into the coinbase scriptSig
//! (`generate_coinbase_input` in `datum_coinbaser.c`) and the pool's verifier finds again
//! (`ratum_prime::verify::locate_pot_byte`). The gateway that builds them, the pool that
//! parses them and the test fixtures that reproduce them must agree byte for byte, so the
//! layout is named once here.
//!
//! ```text
//! <BIP34 height push>
//! <tag push>   primary tag, TAG_SEPARATOR, secondary tag, TAG_END
//! <uid push>   POT_TARGET_PLACEHOLDER, coinbase_unique_id (2, little-endian), prime id
//! ```

/// The byte the gateway writes where the share's PoT (power-of-two difficulty) exponent
/// goes, the C gateway's "placeholder for PoT target". A share carries the exponent and its
/// index, and the pool substitutes it before hashing the coinbase.
pub const POT_TARGET_PLACEHOLDER: u8 = 0xFF;

/// The byte between two coinbase tags in the tag push.
pub const TAG_SEPARATOR: u8 = 0x0F;
/// The byte that ends the tag push, after the last tag.
pub const TAG_END: u8 = 0x00;

/// The uid push before the prime id: the PoT placeholder and the two-byte
/// `mining.coinbase_unique_id`, little-endian.
pub const UID_PUSH_PREFIX_SIZE: usize = 1 + 2;
/// The uid push with no prime id, which the gateway writes only when no pool dictates the
/// coinbase and `prime_id` is zero (the C gateway's 0x03 push).
pub const UID_PUSH_SIZE_NO_PRIME: usize = UID_PUSH_PREFIX_SIZE;
/// The uid push carrying a 32-bit prime id (the version 1 protocol; the C gateway's 0x07
/// push). It can only name a prime id that fits in 32 bits.
pub const UID_PUSH_SIZE_V1: usize = UID_PUSH_PREFIX_SIZE + size_of::<u32>();
/// The uid push carrying the full 64-bit prime id (the version 3 protocol; the C gateway's
/// 0x0B push).
pub const UID_PUSH_SIZE_V3: usize = UID_PUSH_PREFIX_SIZE + size_of::<u64>();

/// The extranonce prefix the gateway writes ahead of the twelve extranonce bytes, so that
/// two jobs built from the same template still differ (`s->enprefix` in `datum_stratum.c`).
pub const ENPREFIX_SIZE: usize = 2;
/// The extranonce push the assembler writes: a one-byte push opcode covering the enprefix
/// and the extranonce.
pub const EXTRANONCE_PUSH_SIZE: usize = 1 + ENPREFIX_SIZE + super::share::EXTRANONCE_SIZE;
/// The marker bytes a tag push carries besides the tags: `TAG_SEPARATOR` between them and
/// `TAG_END` after the last.
pub const TAG_MARKER_BYTES: usize = 2;

/// The data of the tag push: the primary tag, then `TAG_END` when it is the only tag, or
/// `TAG_SEPARATOR`, the secondary tag and `TAG_END` when one follows. With neither tag the
/// push carries a lone `TAG_END`, so the uid push after it is not read as a tag.
///
/// The gateway writes this and the pool's `locate_pot_byte` reads it back, so the layout is
/// here rather than at either end.
pub fn tag_push_data(primary: &[u8], secondary: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(primary.len() + secondary.len() + TAG_MARKER_BYTES);
    if !primary.is_empty() {
        data.extend_from_slice(primary);
        data.push(if secondary.is_empty() { TAG_END } else { TAG_SEPARATOR });
    } else if !secondary.is_empty() {
        data.push(TAG_SEPARATOR);
    }
    if !secondary.is_empty() {
        data.extend_from_slice(secondary);
        data.push(TAG_END);
    }
    if data.is_empty() {
        data.push(TAG_END);
    }
    data
}

/// Where the PoT placeholder sits inside the push [`uid_push`] returns: after the push
/// opcode. A caller records `script.len() + UID_PUSH_POT_AT` before appending it, which is
/// the offset the share's `target_byte_index` names.
pub const UID_PUSH_POT_AT: usize = 1;

/// The uid push: a direct push of the PoT placeholder, the two-byte
/// `mining.coinbase_unique_id` little-endian, and `prime_id` (empty, four bytes for the
/// version 1 protocol, or eight for version 3, which is what its length names).
pub fn uid_push(unique_id: u16, prime_id: &[u8]) -> Vec<u8> {
    let len = UID_PUSH_PREFIX_SIZE + prime_id.len();
    debug_assert!(matches!(len, UID_PUSH_SIZE_NO_PRIME | UID_PUSH_SIZE_V1 | UID_PUSH_SIZE_V3));
    let mut push = Vec::with_capacity(UID_PUSH_POT_AT + len);
    push.push(len as u8);
    push.push(POT_TARGET_PLACEHOLDER);
    push.extend_from_slice(&unique_id.to_le_bytes());
    push.extend_from_slice(prime_id);
    push
}
