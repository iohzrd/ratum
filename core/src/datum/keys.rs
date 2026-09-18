//! A party's signing and box key pairs, and the public halves of them as the wire, the hex settings
//! and the key file hold them.

use dryoc::classic::crypto_box::{
    PublicKey as BoxPublicKey, SecretKey as BoxSecretKey, crypto_box_keypair,
};
use dryoc::classic::crypto_sign::{
    PublicKey as SignPublicKey, SecretKey as SignSecretKey, crypto_sign_keypair,
};

pub(crate) const PUBKEY_LEN: usize = 32;
pub(crate) const PUBLIC_KEYS_LEN: usize = 2 * PUBKEY_LEN;

pub const KEY_PAIRS_LEN: usize = size_of::<SignPublicKey>()
    + size_of::<SignSecretKey>()
    + size_of::<BoxPublicKey>()
    + size_of::<BoxSecretKey>();

/// A party's signing and box public keys. Every encoding, on the wire and in hex, holds the
/// signing key first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKeys {
    pub sign_pk: SignPublicKey,
    pub box_pk: BoxPublicKey,
}

impl PublicKeys {
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEYS_LEN] {
        let mut out = [0u8; PUBLIC_KEYS_LEN];
        let (sign, boxed) = out.split_at_mut(PUBKEY_LEN);
        sign.copy_from_slice(&self.sign_pk);
        boxed.copy_from_slice(&self.box_pk);
        out
    }

    pub fn from_bytes(bytes: &[u8; PUBLIC_KEYS_LEN]) -> Self {
        let [sign_pk, box_pk] = bytes.as_chunks::<PUBKEY_LEN>().0 else {
            unreachable!("PUBLIC_KEYS_LEN bytes hold two keys")
        };
        Self { sign_pk: *sign_pk, box_pk: *box_pk }
    }

    /// The keys at the start of `bytes` and the bytes after them; none when `bytes` is shorter
    /// than `PUBLIC_KEYS_LEN`.
    pub(crate) fn split_from(bytes: &[u8]) -> Option<(Self, &[u8])> {
        let (keys, rest) = bytes.split_first_chunk::<PUBLIC_KEYS_LEN>()?;
        Some((Self::from_bytes(keys), rest))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// The keys `to_hex` encodes; the error reads as the predicate of a sentence naming the
    /// setting.
    pub fn from_hex(s: &str) -> Result<Self, String> {
        const HEX_CHARS: usize = 2 * PUBLIC_KEYS_LEN;
        if s.len() != HEX_CHARS {
            return Err(format!("must be {HEX_CHARS} hex characters, got {}", s.len()));
        }
        let mut bytes = [0u8; PUBLIC_KEYS_LEN];
        hex::decode_to_slice(s, &mut bytes).map_err(|e| format!("is not hex: {e}"))?;
        Ok(Self::from_bytes(&bytes))
    }
}

#[derive(Clone)]
pub struct KeyPairs {
    pub sign_pk: SignPublicKey,
    pub sign_sk: SignSecretKey,
    pub box_pk: BoxPublicKey,
    pub box_sk: BoxSecretKey,
}

impl KeyPairs {
    pub fn generate() -> Self {
        let (sign_pk, sign_sk) = crypto_sign_keypair();
        let (box_pk, box_sk) = crypto_box_keypair();
        Self { sign_pk, sign_sk, box_pk, box_sk }
    }

    pub fn public(&self) -> PublicKeys {
        PublicKeys { sign_pk: self.sign_pk, box_pk: self.box_pk }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(KEY_PAIRS_LEN);
        v.extend_from_slice(&self.sign_pk);
        v.extend_from_slice(&self.sign_sk);
        v.extend_from_slice(&self.box_pk);
        v.extend_from_slice(&self.box_sk);
        v
    }

    pub fn from_bytes(raw: &[u8]) -> Option<Self> {
        if raw.len() != KEY_PAIRS_LEN {
            return None;
        }
        let (sign_pk, rest) = raw.split_at(size_of::<SignPublicKey>());
        let (sign_sk, rest) = rest.split_at(size_of::<SignSecretKey>());
        let (box_pk, box_sk) = rest.split_at(size_of::<BoxPublicKey>());
        Some(Self {
            sign_pk: sign_pk.try_into().ok()?,
            sign_sk: sign_sk.try_into().ok()?,
            box_pk: box_pk.try_into().ok()?,
            box_sk: box_sk.try_into().ok()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_keys_hex_is_the_signing_key_then_the_box_key() {
        let keys = KeyPairs::generate();
        let hexed = keys.public().to_hex();
        assert_eq!(hexed.len(), 128);
        assert_eq!(&hexed[..64], &hex::encode(keys.sign_pk));
        assert_eq!(&hexed[64..], &hex::encode(keys.box_pk));
        assert_eq!(PublicKeys::from_hex(&hexed), Ok(keys.public()));
    }

    #[test]
    fn public_keys_refuse_hex_of_the_wrong_length_or_alphabet() {
        assert_eq!(PublicKeys::from_hex("ab"), Err("must be 128 hex characters, got 2".into()));
        assert!(PublicKeys::from_hex(&"zz".repeat(64)).unwrap_err().starts_with("is not hex"));
    }

    #[test]
    fn public_keys_split_from_the_start_of_a_block() {
        let keys = KeyPairs::generate().public();
        let mut block = keys.to_bytes().to_vec();
        block.push(7);
        assert_eq!(PublicKeys::split_from(&block), Some((keys, &[7u8][..])));
        assert_eq!(PublicKeys::split_from(&block[..PUBLIC_KEYS_LEN - 1]), None);
    }
}
