use super::framing::{self, Header, HeaderKeys, KeyRatchet, STRUCT_END, SessionNonces};
use super::handshake::{Channel, Error, KEYS_LEN, KeyPairs, Signature};
use dryoc::classic::crypto_box::{
    PublicKey as BoxPublicKey, crypto_box_beforenm, crypto_box_seal, crypto_box_seal_open,
};
use dryoc::classic::crypto_sign::{
    PublicKey as SignPublicKey, crypto_sign_detached, crypto_sign_verify_detached,
};
use dryoc::constants::{CRYPTO_BOX_SEALBYTES, CRYPTO_SIGN_BYTES};

/// The hello carries 1 to 200 random pad bytes after `nk`, as the C gateway sends, so the
/// frame length does not identify the user agent.
const HELLO_PAD_MAX: usize = 200;

/// The client side of the DATUM handshake and channel: what the gateway does.
///
/// The pool end is [`super::handshake::accept`] and [`super::handshake::Session`]; this
/// is the other end of the same socket, so the two can be exercised against each other
/// without a C gateway.
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

    /// The motd the pool sent, empty until the handshake response is read.
    pub fn motd(&self) -> &str {
        &self.motd
    }

    /// The hello frame: four public keys, the user agent, and the header-key and nonce seed `nk`,
    /// signed by the long-term key and sealed to the pool's box key.
    pub fn hello(&mut self, pool_box_pk: &BoxPublicKey, user_agent: &str) -> Vec<u8> {
        let mut body = Vec::with_capacity(KEYS_LEN + user_agent.len() + 32);
        body.extend_from_slice(&self.long_term_keys.sign_pk);
        body.extend_from_slice(&self.long_term_keys.box_pk);
        body.extend_from_slice(&self.session_keys.sign_pk);
        body.extend_from_slice(&self.session_keys.box_pk);
        body.extend_from_slice(user_agent.as_bytes());
        body.push(0);
        body.push(STRUCT_END);
        body.extend_from_slice(&self.nk.to_le_bytes());
        let mut pad = [0u8; HELLO_PAD_MAX];
        dryoc::rng::copy_randombytes(&mut pad);
        let pad_len = 1 + usize::from(pad[0]) % HELLO_PAD_MAX;
        body.extend_from_slice(&pad[..pad_len]);

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
        let mut out = Vec::with_capacity(4 + sealed.len());
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

    /// Read the pool's handshake response: verify its signature, check that it echoes the
    /// client's keys, and precompute the channel key. `wire` is the 4-byte header and the
    /// sealed payload.
    pub fn read_handshake_response(
        &mut self,
        wire: &[u8],
        pool_sign_pk: &SignPublicKey,
    ) -> Result<(), Error> {
        let head: [u8; 4] = wire.get(..4).ok_or(Error::Truncated)?.try_into().unwrap();
        let header = self.channel.unmask_header(head);
        if header.proto_cmd != framing::cmd::HANDSHAKE_RESPONSE
            || !header.is_signed
            || !header.is_encrypted_pubkey
        {
            return Err(Error::BadHeader(header));
        }
        let ct = wire.get(4..4 + header.cmd_len as usize).ok_or(Error::Truncated)?;
        if ct.len() < CRYPTO_BOX_SEALBYTES {
            return Err(Error::Truncated);
        }

        let mut plain = vec![0u8; ct.len() - CRYPTO_BOX_SEALBYTES];
        crypto_box_seal_open(&mut plain, ct, &self.session_keys.box_pk, &self.session_keys.box_sk)
            .map_err(|_| Error::Unseal)?;
        if plain.len() < KEYS_LEN + 64 + CRYPTO_SIGN_BYTES {
            return Err(Error::Truncated);
        }

        let (signed, sig) = plain.split_at(plain.len() - CRYPTO_SIGN_BYTES);
        let sig: Signature = sig.try_into().map_err(|_| Error::Truncated)?;
        crypto_sign_verify_detached(&sig, signed, pool_sign_pk).map_err(|_| Error::BadSignature)?;

        if signed[0..32] != self.long_term_keys.sign_pk[..]
            || signed[32..64] != self.long_term_keys.box_pk[..]
            || signed[64..96] != self.session_keys.sign_pk[..]
            || signed[96..128] != self.session_keys.box_pk[..]
        {
            return Err(Error::Malformed("response does not echo the client's keys"));
        }

        let pool_sign: SignPublicKey = signed[128..160].try_into().unwrap();
        let pool_box: BoxPublicKey = signed[160..192].try_into().unwrap();
        let motd = &signed[192..];
        let end = motd.iter().position(|&b| b == 0).unwrap_or(motd.len());
        self.motd = String::from_utf8_lossy(&motd[..end]).into_owned();
        self.pool_session_sign_pk = Some(pool_sign);
        self.channel.set_precomp(
            crypto_box_beforenm(&pool_box, &self.session_keys.box_sk)
                .map_err(|_| Error::Malformed("bad pool session key"))?,
        );
        Ok(())
    }

    /// Encrypt one message to the pool. The gateway never signs channel messages, so
    /// neither does this.
    pub fn encrypt(&mut self, proto_cmd: u8, payload: &[u8]) -> Result<Vec<u8>, Error> {
        self.channel.encrypt(proto_cmd, payload, None)
    }

    pub fn unmask_header(&mut self, bytes: [u8; 4]) -> Header {
        self.channel.unmask_header(bytes)
    }

    /// The handshake response's header, unmasked with the unadvanced server-to-client key
    /// without advancing it: `read_handshake_response` unmasks the same bytes itself. For
    /// reading the response's length before the body arrives.
    pub fn peek_handshake_header(&self, bytes: [u8; 4]) -> Header {
        let key = HeaderKeys::from_nk(self.nk).server_to_client;
        Header::from_bytes((u32::from_le_bytes(bytes) ^ key).to_le_bytes())
    }

    /// Decrypt one message from the pool, checking its session signature when it carries one.
    /// The header flags select the form, as `datum_protocol_server_msg` does: channel
    /// encryption when only `is_encrypted_channel` is set, a sealed box to the session key
    /// when only `is_encrypted_pubkey` is set, and the body as sent when neither or both are
    /// set. Only the channel form advances the receive nonce.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datum::handshake::{accept, open_hello};

    fn server_read_hello(
        wire: &[u8],
        pool: &KeyPairs,
    ) -> Result<crate::datum::handshake::Hello, Error> {
        let mut rx = KeyRatchet::hello();
        let header = rx.unmask(wire[..4].try_into().unwrap());
        open_hello(header, &wire[4..4 + header.cmd_len as usize], pool)
    }

    #[test]
    fn client_and_server_complete_a_handshake_and_exchange_messages_both_ways() {
        let pool = KeyPairs::generate();
        let mut client = Client::new(0x1122_3344);

        let wire = client.hello(&pool.box_pk, "v0.4.1-beta/deadbeef");
        let hello = server_read_hello(&wire, &pool).expect("parse hello");
        assert_eq!(hello.user_agent, "v0.4.1-beta/deadbeef");
        assert_eq!(hello.nk, 0x1122_3344);
        assert_eq!(hello.session_sign_pk, client.session_keys().sign_pk);

        let (response, mut session) = accept(hello, &pool, "RATUM Prime").unwrap();
        client.read_handshake_response(&response, &pool.sign_pk).expect("read response");
        assert_eq!(client.motd(), "RATUM Prime");

        for i in 0..8u8 {
            let signed = vec![i; 40];
            let w = session.encrypt(framing::cmd::MINING, &signed, true).unwrap();
            let h = client.unmask_header(w[..4].try_into().unwrap());
            assert!(h.is_signed);
            assert_eq!(client.decrypt(h, &w[4..]).unwrap(), signed);

            let unsigned = vec![i ^ 0xff; 12];
            let w = session.encrypt(framing::cmd::MINING, &unsigned, false).unwrap();
            let h = client.unmask_header(w[..4].try_into().unwrap());
            assert_eq!(client.decrypt(h, &w[4..]).unwrap(), unsigned);

            let up = vec![i; 33];
            let w = client.encrypt(framing::cmd::MINING, &up).unwrap();
            let h = session.unmask_header(w[..4].try_into().unwrap());
            assert_eq!(h.proto_cmd, framing::cmd::MINING);
            assert_eq!(session.decrypt(h, &w[4..]).unwrap(), up);
        }
    }

    #[test]
    fn a_long_motd_is_read_back_whole() {
        let pool = KeyPairs::generate();
        let mut client = Client::new(9);
        let wire = client.hello(&pool.box_pk, "ua");
        let hello = server_read_hello(&wire, &pool).unwrap();
        let motd = "m".repeat(crate::datum::handshake::MAX_MOTD);
        let (response, _) = accept(hello, &pool, &motd).unwrap();
        client.read_handshake_response(&response, &pool.sign_pk).unwrap();
        assert_eq!(client.motd(), motd);

        let mut client = Client::new(9);
        let wire = client.hello(&pool.box_pk, "ua");
        let hello = server_read_hello(&wire, &pool).unwrap();
        let (response, _) = accept(hello, &pool, "").unwrap();
        client.read_handshake_response(&response, &pool.sign_pk).unwrap();
        assert_eq!(client.motd(), "");
    }

    #[test]
    fn a_response_signed_by_another_pool_is_refused() {
        let pool = KeyPairs::generate();
        let other = KeyPairs::generate();
        let mut client = Client::new(1);
        let wire = client.hello(&pool.box_pk, "ua");
        let hello = server_read_hello(&wire, &pool).unwrap();
        let (response, _) = accept(hello, &pool, "hi").unwrap();
        assert!(matches!(
            client.read_handshake_response(&response, &other.sign_pk),
            Err(Error::BadSignature)
        ));
    }

    #[test]
    fn a_response_to_another_clients_hello_is_refused() {
        let pool = KeyPairs::generate();
        let mut client = Client::new(1);
        let mut other = Client::new(1);
        let _ = client.hello(&pool.box_pk, "ua");
        let wire = other.hello(&pool.box_pk, "ua");
        let hello = server_read_hello(&wire, &pool).unwrap();
        let (response, _) = accept(hello, &pool, "hi").unwrap();
        assert!(matches!(
            client.read_handshake_response(&response, &pool.sign_pk),
            Err(Error::Unseal)
        ));
    }

    #[test]
    fn a_truncated_response_is_refused_rather_than_panicking() {
        let pool = KeyPairs::generate();
        let mut client = Client::new(1);
        let wire = client.hello(&pool.box_pk, "ua");
        let hello = server_read_hello(&wire, &pool).unwrap();
        let (response, _) = accept(hello, &pool, "hi").unwrap();
        for cut in [0, 1, 3, 4, 10, response.len() - 1] {
            let mut c =
                Client::with_key_pairs(KeyPairs::generate(), KeyPairs::generate(), client.nk());
            let _ = c.hello(&pool.box_pk, "ua");
            assert!(
                c.read_handshake_response(&response[..cut], &pool.sign_pk).is_err(),
                "cut at {cut} should not be accepted"
            );
        }
    }

    #[test]
    fn encrypting_or_decrypting_before_the_handshake_is_an_error_not_a_panic() {
        let mut client = Client::new(1);
        assert!(matches!(client.encrypt(framing::cmd::MINING, b"x"), Err(Error::NoChannel)));
        let header = Header { cmd_len: 4, is_encrypted_channel: true, ..Default::default() };
        assert!(matches!(client.decrypt(header, &[0u8; 32]), Err(Error::NoChannel)));
    }

    #[test]
    fn a_plain_frame_after_the_handshake_is_read_as_sent_without_advancing_the_nonce() {
        let pool = KeyPairs::generate();
        let mut client = Client::new(9);
        let wire = client.hello(&pool.box_pk, "ua");
        let hello = server_read_hello(&wire, &pool).unwrap();
        let (response, mut session) = accept(hello, &pool, "hi").unwrap();
        client.read_handshake_response(&response, &pool.sign_pk).unwrap();

        // A plaintext PING, as datum_protocol_server_msg passes through undecrypted.
        let plain =
            Header { cmd_len: 3, proto_cmd: framing::cmd::HELLO_OR_PING, ..Default::default() };
        assert_eq!(client.decrypt(plain, b"abc").unwrap(), b"abc");

        // The channel nonce did not move: the next channel frame still decrypts.
        let wire = session.encrypt(framing::cmd::MINING, b"after", false).unwrap();
        let header = client.unmask_header(wire[..4].try_into().unwrap());
        assert_eq!(client.decrypt(header, &wire[4..]).unwrap(), b"after");

        // A signed plaintext frame with a bad signature is refused.
        let signed = Header {
            cmd_len: 70,
            is_signed: true,
            proto_cmd: framing::cmd::INFO,
            ..Default::default()
        };
        assert!(matches!(client.decrypt(signed, &[0u8; 70]), Err(Error::BadSignature)));
    }

    #[test]
    fn the_channel_desynchronizes_if_a_frame_is_skipped() {
        let pool = KeyPairs::generate();
        let mut client = Client::new(7);
        let wire = client.hello(&pool.box_pk, "ua");
        let hello = server_read_hello(&wire, &pool).unwrap();
        let (response, mut session) = accept(hello, &pool, "hi").unwrap();
        client.read_handshake_response(&response, &pool.sign_pk).unwrap();

        let _skipped = session.encrypt(framing::cmd::MINING, b"one", false).unwrap();
        let second = session.encrypt(framing::cmd::MINING, b"two", false).unwrap();
        let h = client.unmask_header(second[..4].try_into().unwrap());
        assert!(client.decrypt(h, &second[4..]).is_err(), "a skipped frame must not decrypt");
    }
}
