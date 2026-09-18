//! The encrypted channel both sides hold after the handshake: crypto_box under a precomputed key
//! and a per-direction nonce, with a detached signature appended inside the ciphertext where the
//! sender signs. The sealing and signing the handshake itself uses is here too.

use super::framing::{self, FrameHeader, HeaderKeyRatchet, HeaderKeys, SessionNonces};
use dryoc::classic::crypto_box::{
    PublicKey as BoxPublicKey, SecretKey as BoxSecretKey, crypto_box_easy_afternm,
    crypto_box_open_easy_afternm, crypto_box_seal, crypto_box_seal_open,
};
use dryoc::classic::crypto_sign::{
    PublicKey as SignPublicKey, SecretKey as SignSecretKey, crypto_sign_detached,
    crypto_sign_verify_detached,
};
use dryoc::constants::{
    CRYPTO_BOX_BEFORENMBYTES, CRYPTO_BOX_MACBYTES, CRYPTO_BOX_SEALBYTES, CRYPTO_SIGN_BYTES,
};

pub(crate) type PrecompKey = [u8; CRYPTO_BOX_BEFORENMBYTES];
pub(crate) type Signature = [u8; CRYPTO_SIGN_BYTES];

pub(crate) const MAX_PLAINTEXT_LEN: usize = framing::MAX_CMD_LEN - CRYPTO_BOX_MACBYTES;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unexpected handshake frame header: {0:?}")]
    BadHeader(FrameHeader),
    #[error("input truncated")]
    Truncated,
    #[error("could not unseal payload")]
    Unseal,
    #[error("could not seal payload")]
    Seal,
    #[error("signature verification failed")]
    BadSignature,
    #[error("could not sign payload")]
    Sign,
    #[error("malformed payload: {0}")]
    Malformed(&'static str),
    #[error("could not decrypt channel message")]
    Decrypt,
    #[error("could not encrypt channel message")]
    Encrypt,
    #[error("channel not established")]
    NoChannel,
    #[error("no session signing key for the peer")]
    NoVerifyKey,
    #[error("frame too large: {0} bytes")]
    TooLarge(usize),
}

pub struct Channel {
    precomp: Option<PrecompKey>,
    tx_nonce: [u8; framing::NONCE_LEN],
    rx_nonce: [u8; framing::NONCE_LEN],
    tx_header_key: HeaderKeyRatchet,
    rx_header_key: HeaderKeyRatchet,
}

impl Channel {
    pub(crate) fn before_handshake() -> Self {
        Self {
            precomp: None,
            tx_nonce: [0; framing::NONCE_LEN],
            rx_nonce: [0; framing::NONCE_LEN],
            tx_header_key: HeaderKeyRatchet::initial(),
            rx_header_key: HeaderKeyRatchet::initial(),
        }
    }

    pub fn client(keys: HeaderKeys, nonces: SessionNonces) -> Self {
        Self {
            precomp: None,
            tx_nonce: nonces.client_sender,
            rx_nonce: nonces.client_receiver,
            tx_header_key: HeaderKeyRatchet::new(keys.client_to_server),
            rx_header_key: HeaderKeyRatchet::new(keys.server_to_client),
        }
    }

    pub fn server(keys: HeaderKeys, nonces: SessionNonces, precomp: PrecompKey) -> Self {
        Self {
            precomp: Some(precomp),
            tx_nonce: nonces.client_receiver,
            rx_nonce: nonces.client_sender,
            tx_header_key: HeaderKeyRatchet::new(keys.server_to_client),
            rx_header_key: HeaderKeyRatchet::new(keys.client_to_server),
        }
    }

    pub(crate) fn set_precomp(&mut self, precomp: PrecompKey) {
        self.precomp = Some(precomp);
    }

    /// The frame carrying `body`: `header` with the body's length, masked with the next
    /// send key, followed by `body`.
    pub(crate) fn frame(&mut self, header: FrameHeader, body: &[u8]) -> Vec<u8> {
        let header = FrameHeader { cmd_len: body.len() as u32, ..header };
        let mut out = Vec::with_capacity(framing::HEADER_LEN + body.len());
        out.extend_from_slice(&self.tx_header_key.mask(header));
        out.extend_from_slice(body);
        out
    }

    pub fn unmask_header(&mut self, bytes: [u8; framing::HEADER_LEN]) -> FrameHeader {
        self.rx_header_key.unmask(bytes)
    }

    pub fn encrypt(
        &mut self,
        proto_cmd: u8,
        payload: &[u8],
        sign_with: Option<&SignSecretKey>,
    ) -> Result<Vec<u8>, Error> {
        let precomp = self.precomp.as_ref().ok_or(Error::NoChannel)?;
        let signed_body;
        let plain: &[u8] = match sign_with {
            Some(sk) => {
                let mut body = payload.to_vec();
                sign_append(sk, &mut body)?;
                signed_body = body;
                &signed_body
            }
            None => payload,
        };
        if plain.len() > MAX_PLAINTEXT_LEN {
            return Err(Error::TooLarge(plain.len() + CRYPTO_BOX_MACBYTES));
        }
        let ct_len = plain.len() + CRYPTO_BOX_MACBYTES;
        let mut ct = vec![0u8; ct_len];
        crypto_box_easy_afternm(&mut ct, plain, &self.tx_nonce, precomp)
            .map_err(|_| Error::Encrypt)?;
        framing::increment_nonce(&mut self.tx_nonce);
        let header = FrameHeader {
            is_signed: sign_with.is_some(),
            is_encrypted_channel: true,
            proto_cmd,
            ..Default::default()
        };
        Ok(self.frame(header, &ct))
    }

    pub fn decrypt(
        &mut self,
        header: FrameHeader,
        ciphertext: &[u8],
        verify_with: Option<&SignPublicKey>,
    ) -> Result<Vec<u8>, Error> {
        let precomp = self.precomp.as_ref().ok_or(Error::NoChannel)?;
        if ciphertext.len() < CRYPTO_BOX_MACBYTES {
            return Err(Error::Truncated);
        }
        let mut plain = vec![0u8; ciphertext.len() - CRYPTO_BOX_MACBYTES];
        crypto_box_open_easy_afternm(&mut plain, ciphertext, &self.rx_nonce, precomp)
            .map_err(|_| Error::Decrypt)?;
        framing::increment_nonce(&mut self.rx_nonce);
        strip_signature(plain, header, verify_with)
    }
}

pub(crate) fn strip_signature(
    mut plain: Vec<u8>,
    header: FrameHeader,
    verify_with: Option<&SignPublicKey>,
) -> Result<Vec<u8>, Error> {
    if header.is_signed {
        let (signed, sig) = split_signed(&plain)?;
        let pk = verify_with.ok_or(Error::NoVerifyKey)?;
        verify(&sig, signed, pk)?;
        let signed_len = signed.len();
        plain.truncate(signed_len);
    }
    Ok(plain)
}

/// Appends the detached signature of `body` to it.
pub(crate) fn sign_append(sk: &SignSecretKey, body: &mut Vec<u8>) -> Result<(), Error> {
    let mut sig: Signature = [0u8; CRYPTO_SIGN_BYTES];
    crypto_sign_detached(&mut sig, body, sk).map_err(|_| Error::Sign)?;
    body.extend_from_slice(&sig);
    Ok(())
}

/// The signed bytes and the detached signature that follows them.
pub(crate) fn split_signed(plain: &[u8]) -> Result<(&[u8], Signature), Error> {
    if plain.len() < CRYPTO_SIGN_BYTES {
        return Err(Error::Truncated);
    }
    let (signed, sig) = plain.split_at(plain.len() - CRYPTO_SIGN_BYTES);
    Ok((signed, sig.try_into().expect("CRYPTO_SIGN_BYTES bytes")))
}

pub(crate) fn verify(sig: &Signature, signed: &[u8], pk: &SignPublicKey) -> Result<(), Error> {
    crypto_sign_verify_detached(sig, signed, pk).map_err(|_| Error::BadSignature)
}

/// `body` signed with `sk`, the signature appended, and sealed to `pk`.
pub(crate) fn seal_signed(
    sk: &SignSecretKey,
    pk: &BoxPublicKey,
    mut body: Vec<u8>,
) -> Result<Vec<u8>, Error> {
    sign_append(sk, &mut body)?;
    seal(pk, &body)
}

/// `body` sealed to `pk`: readable by the holder of its secret key alone.
pub(crate) fn seal(pk: &BoxPublicKey, body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut sealed = vec![0u8; body.len() + CRYPTO_BOX_SEALBYTES];
    crypto_box_seal(&mut sealed, body, pk).map_err(|_| Error::Seal)?;
    Ok(sealed)
}

pub(crate) fn open_sealed(
    pk: &BoxPublicKey,
    sk: &BoxSecretKey,
    sealed: &[u8],
) -> Result<Vec<u8>, Error> {
    if sealed.len() < CRYPTO_BOX_SEALBYTES {
        return Err(Error::Truncated);
    }
    let mut plain = vec![0u8; sealed.len() - CRYPTO_BOX_SEALBYTES];
    crypto_box_seal_open(&mut plain, sealed, pk, sk).map_err(|_| Error::Unseal)?;
    Ok(plain)
}
