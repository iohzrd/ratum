use super::framing::{self, Header, HeaderKeys, KeyRatchet, STRUCT_END, SessionNonces};
use dryoc::classic::crypto_box::{
    PublicKey as BoxPublicKey, SecretKey as BoxSecretKey, crypto_box_beforenm,
    crypto_box_easy_afternm, crypto_box_keypair, crypto_box_open_easy_afternm, crypto_box_seal,
    crypto_box_seal_open,
};
use dryoc::classic::crypto_sign::{
    PublicKey as SignPublicKey, SecretKey as SignSecretKey, crypto_sign_detached,
    crypto_sign_keypair, crypto_sign_verify_detached,
};
use dryoc::constants::{
    CRYPTO_BOX_BEFORENMBYTES, CRYPTO_BOX_MACBYTES, CRYPTO_BOX_SEALBYTES, CRYPTO_SIGN_BYTES,
};

pub(crate) type PrecompKey = [u8; CRYPTO_BOX_BEFORENMBYTES];
pub(crate) type Signature = [u8; CRYPTO_SIGN_BYTES];

pub const PUBKEY_LEN: usize = 32;
pub(crate) const HELLO_KEYS: usize = 4;
pub(crate) const KEYS_LEN: usize = HELLO_KEYS * PUBKEY_LEN;
pub(crate) const POOL_SIGN_KEY_INDEX: usize = HELLO_KEYS;
pub(crate) const POOL_BOX_KEY_INDEX: usize = HELLO_KEYS + 1;
pub(crate) const RESPONSE_KEYS_LEN: usize = (POOL_BOX_KEY_INDEX + 1) * PUBKEY_LEN;

const MAX_USER_AGENT: usize = 256;
const AFTER_UA_LEN: usize = 1 + size_of::<u32>();
pub const MAX_MOTD: usize = 511;

pub(crate) fn key_at(block: &[u8], n: usize) -> Option<&[u8]> {
    block.get(n * PUBKEY_LEN..(n + 1) * PUBKEY_LEN)
}

pub(crate) fn pubkey_at(block: &[u8], n: usize) -> [u8; PUBKEY_LEN] {
    key_at(block, n).expect("the caller checked the length").try_into().expect("PUBKEY_LEN bytes")
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unexpected handshake frame header: {0:?}")]
    BadHeader(Header),
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

    pub fn pubkey_hex(&self) -> String {
        let mut v = Vec::with_capacity(2 * PUBKEY_LEN);
        v.extend_from_slice(&self.sign_pk);
        v.extend_from_slice(&self.box_pk);
        hex::encode(v)
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

pub const KEY_PAIRS_LEN: usize = size_of::<SignPublicKey>()
    + size_of::<SignSecretKey>()
    + size_of::<BoxPublicKey>()
    + size_of::<BoxSecretKey>();

pub const DRS_MARKER: [u8; 4] = *b"DRS\x01";
pub const DRS_RESUME_PRESENT: u8 = 1;
pub const DRS_FLAG_AT: usize = DRS_MARKER.len();
pub const DRS_TOKEN_AT: usize = DRS_FLAG_AT + 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Generation {
    V1,
    V3 { resume: Option<super::messages::ResumeToken> },
}

#[derive(Clone, Debug)]
pub struct Hello {
    pub client_sign_pk: SignPublicKey,
    pub client_box_pk: BoxPublicKey,
    pub session_sign_pk: SignPublicKey,
    pub session_box_pk: BoxPublicKey,
    pub user_agent: String,
    pub nk: u32,
    pub generation: Generation,
}

pub fn open_hello(header: Header, payload: &[u8], pool: &KeyPairs) -> Result<Hello, Error> {
    if header.proto_cmd != framing::cmd::HELLO_OR_PING
        || !header.is_signed
        || !header.is_encrypted_pubkey
        || header.is_encrypted_channel
    {
        return Err(Error::BadHeader(header));
    }
    if payload.len() < CRYPTO_BOX_SEALBYTES {
        return Err(Error::Truncated);
    }
    let mut plain = vec![0u8; payload.len() - CRYPTO_BOX_SEALBYTES];
    crypto_box_seal_open(&mut plain, payload, &pool.box_pk, &pool.box_sk)
        .map_err(|_| Error::Unseal)?;

    if plain.len() < KEYS_LEN + CRYPTO_SIGN_BYTES {
        return Err(Error::Truncated);
    }
    let (signed, sig) = plain.split_at(plain.len() - CRYPTO_SIGN_BYTES);
    let sig: Signature = sig.try_into().map_err(|_| Error::Truncated)?;
    let client_sign_pk: SignPublicKey = pubkey_at(signed, 0);
    crypto_sign_verify_detached(&sig, signed, &client_sign_pk).map_err(|_| Error::BadSignature)?;

    let client_box_pk: BoxPublicKey = pubkey_at(signed, 1);
    let session_sign_pk: SignPublicKey = pubkey_at(signed, 2);
    let session_box_pk: BoxPublicKey = pubkey_at(signed, 3);

    let rest = &signed[KEYS_LEN..];
    let nul = rest.iter().position(|&b| b == 0).ok_or(Error::Malformed("no UA terminator"))?;
    let user_agent = String::from_utf8_lossy(&rest[..nul.min(MAX_USER_AGENT)]).into_owned();
    let after = &rest[nul + 1..];
    if after.len() < AFTER_UA_LEN {
        return Err(Error::Truncated);
    }
    if after[0] != STRUCT_END {
        return Err(Error::Malformed("no 0xFE after user agent"));
    }
    let nk = u32::from_le_bytes(after[1..AFTER_UA_LEN].try_into().expect("AFTER_UA_LEN - 1 bytes"));

    let tail = &after[AFTER_UA_LEN..];
    let generation = if tail.len() > DRS_FLAG_AT && tail[..DRS_FLAG_AT] == DRS_MARKER {
        let resume = if tail[DRS_FLAG_AT] != 0 {
            let token: super::messages::ResumeToken = tail
                .get(DRS_TOKEN_AT..DRS_TOKEN_AT + super::messages::RESUME_TOKEN_LEN)
                .ok_or(Error::Malformed("DRS flag set without a token"))?
                .try_into()
                .expect("length checked");
            Some(token)
        } else {
            None
        };
        Generation::V3 { resume }
    } else {
        Generation::V1
    };

    Ok(Hello {
        client_sign_pk,
        client_box_pk,
        session_sign_pk,
        session_box_pk,
        user_agent,
        nk,
        generation,
    })
}

pub struct Channel {
    precomp: Option<PrecompKey>,
    tx_nonce: [u8; framing::NONCE_LEN],
    rx_nonce: [u8; framing::NONCE_LEN],
    tx_headers: KeyRatchet,
    rx_headers: KeyRatchet,
}

impl Channel {
    pub fn before_handshake() -> Self {
        Self {
            precomp: None,
            tx_nonce: [0; framing::NONCE_LEN],
            rx_nonce: [0; framing::NONCE_LEN],
            tx_headers: KeyRatchet::hello(),
            rx_headers: KeyRatchet::hello(),
        }
    }

    pub fn new(
        tx_headers: KeyRatchet,
        rx_headers: KeyRatchet,
        tx_nonce: [u8; framing::NONCE_LEN],
        rx_nonce: [u8; framing::NONCE_LEN],
        precomp: Option<PrecompKey>,
    ) -> Self {
        Self { precomp, tx_nonce, rx_nonce, tx_headers, rx_headers }
    }

    pub fn set_precomp(&mut self, precomp: PrecompKey) {
        self.precomp = Some(precomp);
    }

    pub fn mask_header(&mut self, header: Header) -> [u8; framing::HEADER_LEN] {
        self.tx_headers.mask(header)
    }

    pub fn unmask_header(&mut self, bytes: [u8; framing::HEADER_LEN]) -> Header {
        self.rx_headers.unmask(bytes)
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
                let mut sig: Signature = [0u8; CRYPTO_SIGN_BYTES];
                crypto_sign_detached(&mut sig, payload, sk).map_err(|_| Error::Sign)?;
                let mut body = Vec::with_capacity(payload.len() + CRYPTO_SIGN_BYTES);
                body.extend_from_slice(payload);
                body.extend_from_slice(&sig);
                signed_body = body;
                &signed_body
            }
            None => payload,
        };
        let ct_len = plain.len() + CRYPTO_BOX_MACBYTES;
        if ct_len as u64 > u64::from(framing::MAX_CMD_LEN) {
            return Err(Error::TooLarge(ct_len));
        }
        let mut ct = vec![0u8; ct_len];
        crypto_box_easy_afternm(&mut ct, plain, &self.tx_nonce, precomp)
            .map_err(|_| Error::Encrypt)?;
        framing::increment_nonce(&mut self.tx_nonce);
        let header = Header {
            cmd_len: ct.len() as u32,
            is_signed: sign_with.is_some(),
            is_encrypted_channel: true,
            proto_cmd,
            ..Default::default()
        };
        let mut out = Vec::with_capacity(framing::HEADER_LEN + ct.len());
        out.extend_from_slice(&self.tx_headers.mask(header));
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn decrypt(
        &mut self,
        header: Header,
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

pub fn strip_signature(
    mut plain: Vec<u8>,
    header: Header,
    verify_with: Option<&SignPublicKey>,
) -> Result<Vec<u8>, Error> {
    if header.is_signed {
        if plain.len() < CRYPTO_SIGN_BYTES {
            return Err(Error::Truncated);
        }
        let pk = verify_with.ok_or(Error::NoVerifyKey)?;
        let (signed, sig) = plain.split_at(plain.len() - CRYPTO_SIGN_BYTES);
        let sig: Signature = sig.try_into().map_err(|_| Error::Truncated)?;
        crypto_sign_verify_detached(&sig, signed, pk).map_err(|_| Error::BadSignature)?;
        plain.truncate(plain.len() - CRYPTO_SIGN_BYTES);
    }
    Ok(plain)
}

pub struct Session {
    channel: Channel,
    session_sign_sk: SignSecretKey,
    hello: Hello,
}

impl Session {
    pub fn encrypt(&mut self, proto_cmd: u8, payload: &[u8], sign: bool) -> Result<Vec<u8>, Error> {
        self.channel.encrypt(proto_cmd, payload, sign.then_some(&self.session_sign_sk))
    }

    pub fn unmask_header(&mut self, bytes: [u8; framing::HEADER_LEN]) -> Header {
        self.channel.unmask_header(bytes)
    }

    pub fn decrypt(&mut self, header: Header, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        if !header.is_encrypted_channel || header.is_encrypted_pubkey {
            return Err(Error::Malformed(
                "client message is not a channel-encrypted frame (sealed or plain)",
            ));
        }
        self.channel.decrypt(header, ciphertext, Some(&self.hello.session_sign_pk))
    }
}

pub fn accept(hello: Hello, pool: &KeyPairs, motd: &str) -> Result<(Vec<u8>, Session), Error> {
    let (session_sign_pk, session_sign_sk) = crypto_sign_keypair();
    let (session_box_pk, session_box_sk) = crypto_box_keypair();

    let mut body = Vec::with_capacity(RESPONSE_KEYS_LEN + motd.len() + 1);
    body.extend_from_slice(&hello.client_sign_pk);
    body.extend_from_slice(&hello.client_box_pk);
    body.extend_from_slice(&hello.session_sign_pk);
    body.extend_from_slice(&hello.session_box_pk);
    body.extend_from_slice(&session_sign_pk);
    body.extend_from_slice(&session_box_pk);
    let motd_bytes = motd.as_bytes();
    let motd_bytes = &motd_bytes[..motd_bytes.len().min(MAX_MOTD)];
    body.extend_from_slice(motd_bytes);
    body.push(0);

    let mut sig: Signature = [0u8; CRYPTO_SIGN_BYTES];
    crypto_sign_detached(&mut sig, &body, &pool.sign_sk).map_err(|_| Error::Sign)?;
    body.extend_from_slice(&sig);

    let mut sealed = vec![0u8; body.len() + CRYPTO_BOX_SEALBYTES];
    crypto_box_seal(&mut sealed, &body, &hello.session_box_pk).map_err(|_| Error::Seal)?;
    if sealed.len() as u32 > framing::MAX_CMD_LEN {
        return Err(Error::TooLarge(sealed.len()));
    }

    let keys = HeaderKeys::from_nk(hello.nk);
    let mut tx_headers = KeyRatchet::new(keys.server_to_client);
    let header = Header {
        cmd_len: sealed.len() as u32,
        is_signed: true,
        is_encrypted_pubkey: true,
        proto_cmd: framing::cmd::HANDSHAKE_RESPONSE,
        ..Default::default()
    };
    let mut out = Vec::with_capacity(framing::HEADER_LEN + sealed.len());
    out.extend_from_slice(&tx_headers.mask(header));
    out.extend_from_slice(&sealed);

    let precomp = crypto_box_beforenm(&hello.session_box_pk, &session_box_sk)
        .map_err(|_| Error::Malformed("bad session key"))?;
    let nonces = SessionNonces::derive(hello.nk, &hello.session_sign_pk);

    Ok((
        out,
        Session {
            channel: Channel::new(
                tx_headers,
                KeyRatchet::new(keys.client_to_server),
                nonces.client_receiver,
                nonces.client_sender,
                Some(precomp),
            ),
            session_sign_sk,
            hello,
        },
    ))
}

#[cfg(test)]
mod tests {

    fn client_with_generated_keys(nk: u32) -> Client {
        Client::with_key_pairs(KeyPairs::generate(), KeyPairs::generate(), nk)
    }
    use super::*;
    use crate::datum::client::Client;

    fn server_read_hello(wire: &[u8], pool: &KeyPairs) -> Result<Hello, Error> {
        let mut rx = KeyRatchet::hello();
        let header = rx.unmask(wire[..4].try_into().unwrap());
        open_hello(header, &wire[4..4 + header.cmd_len as usize], pool)
    }

    #[test]
    fn hello_tail_bytes_are_ignored() {
        let pool = KeyPairs::generate();
        let long_term = KeyPairs::generate();
        let session = KeyPairs::generate();
        let nk: u32 = 0x1122_3344;

        let mut body = Vec::new();
        body.extend_from_slice(&long_term.sign_pk);
        body.extend_from_slice(&long_term.box_pk);
        body.extend_from_slice(&session.sign_pk);
        body.extend_from_slice(&session.box_pk);
        body.extend_from_slice(b"v0.4.1-beta/deadbeef");
        body.push(0);
        body.push(STRUCT_END);
        body.extend_from_slice(&nk.to_le_bytes());
        body.extend_from_slice(&[0xAB; 17]);
        let mut sig: Signature = [0u8; CRYPTO_SIGN_BYTES];
        crypto_sign_detached(&mut sig, &body, &long_term.sign_sk).unwrap();
        body.extend_from_slice(&sig);
        let mut sealed = vec![0u8; body.len() + CRYPTO_BOX_SEALBYTES];
        crypto_box_seal(&mut sealed, &body, &pool.box_pk).unwrap();

        let header = Header {
            cmd_len: sealed.len() as u32,
            is_signed: true,
            is_encrypted_pubkey: true,
            proto_cmd: framing::cmd::HELLO_OR_PING,
            ..Default::default()
        };
        let hello = open_hello(header, &sealed, &pool).expect("pad bytes are not checked");
        assert_eq!(hello.user_agent, "v0.4.1-beta/deadbeef");
        assert_eq!(hello.nk, nk);
        assert_eq!(hello.session_sign_pk, session.sign_pk);
    }

    #[test]
    fn rejects_hello_sealed_to_another_pool() {
        let pool = KeyPairs::generate();
        let other = KeyPairs::generate();
        let mut client = client_with_generated_keys(7);
        let wire = client.hello(&other.box_pk, "v0.4.1-beta");
        assert!(matches!(server_read_hello(&wire, &pool), Err(Error::Unseal)));
    }

    #[test]
    fn rejects_hello_whose_sealed_bytes_are_altered() {
        let pool = KeyPairs::generate();
        let mut client = client_with_generated_keys(7);
        let mut bad = client.hello(&pool.box_pk, "v0.4.1-beta");
        let n = bad.len();
        bad[n - 1] ^= 0x01;
        assert!(matches!(server_read_hello(&bad, &pool), Err(Error::Unseal)));
    }

    #[test]
    fn rejects_wrong_command() {
        let pool = KeyPairs::generate();
        let header = Header {
            cmd_len: 100,
            is_signed: true,
            is_encrypted_pubkey: true,
            proto_cmd: framing::cmd::MINING,
            ..Default::default()
        };
        assert!(matches!(open_hello(header, &[0u8; 100], &pool), Err(Error::BadHeader(_))));
    }

    #[test]
    fn key_pairs_pubkey_hex_is_128_chars() {
        let keys = KeyPairs::generate();
        let hexed = keys.pubkey_hex();
        assert_eq!(hexed.len(), 128);
        assert_eq!(&hexed[..64], &hex::encode(keys.sign_pk));
        assert_eq!(&hexed[64..], &hex::encode(keys.box_pk));
    }
}
