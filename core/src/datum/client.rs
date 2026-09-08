use super::framing::{self, Header, HeaderKeys, KeyRatchet, STRUCT_END, SessionNonces};
use super::handshake::{
    Channel, Error, Generation, KEYS_LEN, KeyPairs, POOL_BOX_KEY_INDEX, POOL_SIGN_KEY_INDEX,
    RESPONSE_KEYS_LEN, Signature, key_at,
};
use dryoc::classic::crypto_box::{
    PublicKey as BoxPublicKey, crypto_box_beforenm, crypto_box_seal, crypto_box_seal_open,
};
use dryoc::classic::crypto_sign::{
    PublicKey as SignPublicKey, crypto_sign_detached, crypto_sign_verify_detached,
};
use dryoc::constants::{CRYPTO_BOX_SEALBYTES, CRYPTO_SIGN_BYTES};

const HELLO_PAD_MAX: usize = 200;

const HELLO_TAIL_MAX: usize = 1
    + 1
    + size_of::<u32>()
    + super::handshake::DRS_TOKEN_AT
    + super::messages::RESUME_TOKEN_LEN
    + HELLO_PAD_MAX
    + CRYPTO_SIGN_BYTES;

pub struct Client {
    long_term_keys: KeyPairs,
    session_keys: KeyPairs,
    nk: u32,
    channel: Channel,
    pool_session_sign_pk: Option<SignPublicKey>,
    motd: String,
}

impl Client {
    pub fn new(nk: u32) -> Self {
        Client::with_key_pairs(KeyPairs::generate(), KeyPairs::generate(), nk)
    }

    pub fn with_key_pairs(long_term_keys: KeyPairs, session_keys: KeyPairs, nk: u32) -> Self {
        Client {
            long_term_keys,
            session_keys,
            nk,
            channel: Channel::before_handshake(),
            pool_session_sign_pk: None,
            motd: String::new(),
        }
    }

    pub fn nk(&self) -> u32 {
        self.nk
    }

    pub fn long_term_keys(&self) -> &KeyPairs {
        &self.long_term_keys
    }

    pub fn session_keys(&self) -> &KeyPairs {
        &self.session_keys
    }

    pub fn motd(&self) -> &str {
        &self.motd
    }

    pub fn hello(&mut self, pool_box_pk: &BoxPublicKey, user_agent: &str) -> Vec<u8> {
        self.hello_with(pool_box_pk, user_agent, Generation::V1)
    }

    pub fn hello_resumable(
        &mut self,
        pool_box_pk: &BoxPublicKey,
        user_agent: &str,
        token: Option<&super::messages::ResumeToken>,
    ) -> Vec<u8> {
        self.hello_with(pool_box_pk, user_agent, Generation::V3 { resume: token.copied() })
    }

    fn hello_with(
        &mut self,
        pool_box_pk: &BoxPublicKey,
        user_agent: &str,
        generation: Generation,
    ) -> Vec<u8> {
        let mut body = Vec::with_capacity(KEYS_LEN + user_agent.len() + HELLO_TAIL_MAX);
        body.extend_from_slice(&self.long_term_keys.sign_pk);
        body.extend_from_slice(&self.long_term_keys.box_pk);
        body.extend_from_slice(&self.session_keys.sign_pk);
        body.extend_from_slice(&self.session_keys.box_pk);
        body.extend_from_slice(user_agent.as_bytes());
        body.push(0);
        body.push(STRUCT_END);
        body.extend_from_slice(&self.nk.to_le_bytes());
        if let Generation::V3 { resume } = generation {
            body.extend_from_slice(&super::handshake::DRS_MARKER);
            match resume {
                Some(t) => {
                    body.push(super::handshake::DRS_RESUME_PRESENT);
                    body.extend_from_slice(&t);
                }
                None => body.push(0),
            }
        }
        let mut r = [0u8; 2];
        dryoc::rng::copy_randombytes(&mut r);
        let pad_len = 1 + usize::from(r[0]) % HELLO_PAD_MAX;
        body.resize(body.len() + pad_len, r[1]);

        let mut sig: Signature = [0u8; CRYPTO_SIGN_BYTES];
        crypto_sign_detached(&mut sig, &body, &self.long_term_keys.sign_sk).expect("sign hello");
        body.extend_from_slice(&sig);

        let mut sealed = vec![0u8; body.len() + CRYPTO_BOX_SEALBYTES];
        crypto_box_seal(&mut sealed, &body, pool_box_pk).expect("seal hello");

        let header = Header {
            cmd_len: sealed.len() as u32,
            is_signed: true,
            is_encrypted_pubkey: true,
            proto_cmd: framing::cmd::HELLO_OR_PING,
            ..Default::default()
        };
        let mut out = Vec::with_capacity(framing::HEADER_LEN + sealed.len());
        out.extend_from_slice(&self.channel.mask_header(header));
        out.extend_from_slice(&sealed);

        let keys = HeaderKeys::from_nk(self.nk);
        let nonces = SessionNonces::derive(self.nk, &self.session_keys.sign_pk);
        self.channel = Channel::new(
            KeyRatchet::new(keys.client_to_server),
            KeyRatchet::new(keys.server_to_client),
            nonces.client_sender,
            nonces.client_receiver,
            None,
        );
        out
    }

    pub fn read_handshake_response(
        &mut self,
        wire: &[u8],
        pool_sign_pk: &SignPublicKey,
    ) -> Result<(), Error> {
        let head: [u8; framing::HEADER_LEN] =
            wire.get(..framing::HEADER_LEN).ok_or(Error::Truncated)?.try_into().unwrap();
        let header = self.channel.unmask_header(head);
        if header.proto_cmd != framing::cmd::HANDSHAKE_RESPONSE
            || !header.is_signed
            || !header.is_encrypted_pubkey
        {
            return Err(Error::BadHeader(header));
        }
        let ct = wire
            .get(framing::HEADER_LEN..framing::HEADER_LEN + header.cmd_len as usize)
            .ok_or(Error::Truncated)?;
        if ct.len() < CRYPTO_BOX_SEALBYTES {
            return Err(Error::Truncated);
        }

        let mut plain = vec![0u8; ct.len() - CRYPTO_BOX_SEALBYTES];
        crypto_box_seal_open(&mut plain, ct, &self.session_keys.box_pk, &self.session_keys.box_sk)
            .map_err(|_| Error::Unseal)?;
        if plain.len() < RESPONSE_KEYS_LEN + CRYPTO_SIGN_BYTES {
            return Err(Error::Truncated);
        }

        let (signed, sig) = plain.split_at(plain.len() - CRYPTO_SIGN_BYTES);
        let sig: Signature = sig.try_into().map_err(|_| Error::Truncated)?;
        crypto_sign_verify_detached(&sig, signed, pool_sign_pk).map_err(|_| Error::BadSignature)?;

        let sent = [
            &self.long_term_keys.sign_pk[..],
            &self.long_term_keys.box_pk[..],
            &self.session_keys.sign_pk[..],
            &self.session_keys.box_pk[..],
        ];
        if sent.iter().enumerate().any(|(n, k)| key_at(signed, n) != Some(*k)) {
            return Err(Error::Malformed("response does not echo the client's keys"));
        }

        let key = |n| key_at(signed, n).expect("length checked").try_into().expect("PUBKEY_LEN");
        let pool_sign: SignPublicKey = key(POOL_SIGN_KEY_INDEX);
        let pool_box: BoxPublicKey = key(POOL_BOX_KEY_INDEX);
        let motd = &signed[RESPONSE_KEYS_LEN..];
        let end = motd.iter().position(|&b| b == 0).unwrap_or(motd.len());
        self.motd = String::from_utf8_lossy(&motd[..end]).into_owned();
        self.pool_session_sign_pk = Some(pool_sign);
        self.channel.set_precomp(
            crypto_box_beforenm(&pool_box, &self.session_keys.box_sk)
                .map_err(|_| Error::Malformed("bad pool session key"))?,
        );
        Ok(())
    }

    pub fn encrypt(&mut self, proto_cmd: u8, payload: &[u8]) -> Result<Vec<u8>, Error> {
        self.channel.encrypt(proto_cmd, payload, None)
    }

    pub fn unmask_header(&mut self, bytes: [u8; framing::HEADER_LEN]) -> Header {
        self.channel.unmask_header(bytes)
    }

    pub fn peek_handshake_header(&self, bytes: [u8; framing::HEADER_LEN]) -> Header {
        let key = HeaderKeys::from_nk(self.nk).server_to_client;
        Header::from_bytes((u32::from_le_bytes(bytes) ^ key).to_le_bytes())
    }

    pub fn decrypt(&mut self, header: Header, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let verify = self.pool_session_sign_pk.as_ref();
        match (header.is_encrypted_channel, header.is_encrypted_pubkey) {
            (true, false) => self.channel.decrypt(header, ciphertext, verify),
            (false, true) => {
                if ciphertext.len() < CRYPTO_BOX_SEALBYTES {
                    return Err(Error::Truncated);
                }
                let mut plain = vec![0u8; ciphertext.len() - CRYPTO_BOX_SEALBYTES];
                crypto_box_seal_open(
                    &mut plain,
                    ciphertext,
                    &self.session_keys.box_pk,
                    &self.session_keys.box_sk,
                )
                .map_err(|_| Error::Unseal)?;
                super::handshake::strip_signature(plain, header, verify)
            }
            _ => super::handshake::strip_signature(ciphertext.to_vec(), header, verify),
        }
    }
}
