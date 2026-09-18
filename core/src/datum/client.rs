//! The gateway's end of the handshake: it seals the hello to the pool's box key, reads the response
//! the pool signs, and holds the channel every later frame runs through.

use super::channel::{
    Channel, Error, open_sealed, seal_signed, split_signed, strip_signature, verify,
};
use super::framing::{self, FrameHeader, HeaderKeys, SessionNonces};
use super::handshake::{
    DRS_MARKER, DRS_RESUME_PRESENT, DRS_TOKEN_AT, ProtocolVersion, RESUME_TOKEN_LEN,
};
use super::keys::{KeyPairs, PUBLIC_KEYS_LEN, PublicKeys};
use super::messages::STRUCT_END;
use bytes::BufMut as _;
use dryoc::classic::crypto_box::{PublicKey as BoxPublicKey, crypto_box_beforenm};
use dryoc::classic::crypto_sign::PublicKey as SignPublicKey;
use dryoc::constants::CRYPTO_SIGN_BYTES;

const MAX_HELLO_PAD_LEN: usize = 200;

const MAX_HELLO_TAIL_LEN: usize = 1
    + 1
    + size_of::<u32>()
    + DRS_TOKEN_AT
    + RESUME_TOKEN_LEN
    + MAX_HELLO_PAD_LEN
    + CRYPTO_SIGN_BYTES;

pub struct ClientChannel {
    long_term_keys: KeyPairs,
    session_keys: KeyPairs,
    nk: u32,
    channel: Channel,
    pool_session_sign_pk: Option<SignPublicKey>,
    motd: String,
}

impl ClientChannel {
    pub fn with_key_pairs(long_term_keys: KeyPairs, session_keys: KeyPairs, nk: u32) -> Self {
        Self {
            long_term_keys,
            session_keys,
            nk,
            channel: Channel::before_handshake(),
            pool_session_sign_pk: None,
            motd: String::new(),
        }
    }

    pub fn motd(&self) -> &str {
        &self.motd
    }

    /// The hello frame that opens a session, sealed to the pool's box key; a version 3
    /// hello carries the DRS extension and the resume token of the session it continues.
    pub fn hello(
        &mut self,
        pool_box_pk: &BoxPublicKey,
        user_agent: &str,
        protocol_version: ProtocolVersion,
    ) -> Vec<u8> {
        let mut body =
            Vec::with_capacity(2 * PUBLIC_KEYS_LEN + user_agent.len() + MAX_HELLO_TAIL_LEN);
        body.put_slice(&self.long_term_keys.public().to_bytes());
        body.put_slice(&self.session_keys.public().to_bytes());
        body.put_slice(user_agent.as_bytes());
        body.put_u8(0);
        body.put_u8(STRUCT_END);
        body.put_u32_le(self.nk);
        if let ProtocolVersion::V3 { resume } = protocol_version {
            body.put_slice(&DRS_MARKER);
            match resume {
                Some(t) => {
                    body.put_u8(DRS_RESUME_PRESENT);
                    body.put_slice(&t);
                }
                None => body.put_u8(0),
            }
        }
        let r = crate::rand::bytes::<2>();
        let pad_len = 1 + usize::from(r[0]) % MAX_HELLO_PAD_LEN;
        body.resize(body.len() + pad_len, r[1]);

        let sealed = seal_signed(&self.long_term_keys.sign_sk, pool_box_pk, body)
            .expect("sign and seal hello");
        let header = FrameHeader {
            is_signed: true,
            is_encrypted_pubkey: true,
            proto_cmd: framing::cmd::HELLO_OR_PING,
            ..Default::default()
        };
        let out = self.channel.frame(header, &sealed);

        let keys = HeaderKeys::from_nk(self.nk);
        let nonces = SessionNonces::derive(self.nk, &self.session_keys.sign_pk);
        self.channel = Channel::client(keys, nonces);
        out
    }

    /// Reads the pool's handshake response: `header` as `unmask_header` returned it and
    /// `body` the `header.cmd_len` bytes that followed.
    pub fn read_handshake_response(
        &mut self,
        header: FrameHeader,
        body: &[u8],
        pool_sign_pk: &SignPublicKey,
    ) -> Result<(), Error> {
        if header.proto_cmd != framing::cmd::HANDSHAKE_RESPONSE
            || !header.is_signed
            || !header.is_encrypted_pubkey
        {
            return Err(Error::BadHeader(header));
        }
        let plain = open_sealed(&self.session_keys.box_pk, &self.session_keys.box_sk, body)?;
        let (signed, sig) = split_signed(&plain)?;
        let (client, rest) = PublicKeys::split_from(signed).ok_or(Error::Truncated)?;
        let (session, rest) = PublicKeys::split_from(rest).ok_or(Error::Truncated)?;
        let (pool_session, motd) = PublicKeys::split_from(rest).ok_or(Error::Truncated)?;
        verify(&sig, signed, pool_sign_pk)?;
        if client != self.long_term_keys.public() || session != self.session_keys.public() {
            return Err(Error::Malformed("response does not echo the client's keys"));
        }

        let end = motd.iter().position(|&b| b == 0).unwrap_or(motd.len());
        self.motd = String::from_utf8_lossy(&motd[..end]).into_owned();
        self.pool_session_sign_pk = Some(pool_session.sign_pk);
        self.channel.set_precomp(
            crypto_box_beforenm(&pool_session.box_pk, &self.session_keys.box_sk)
                .map_err(|_| Error::Malformed("bad pool session key"))?,
        );
        Ok(())
    }

    pub fn encrypt(&mut self, proto_cmd: u8, payload: &[u8]) -> Result<Vec<u8>, Error> {
        self.channel.encrypt(proto_cmd, payload, None)
    }

    pub fn unmask_header(&mut self, bytes: [u8; framing::HEADER_LEN]) -> FrameHeader {
        self.channel.unmask_header(bytes)
    }

    /// Opens a frame the pool sent after the handshake: encrypted on the channel, or sealed to
    /// the session's box key. A frame with neither flag, or with both, is refused: its bytes
    /// carry no MAC, so anyone who derives the header mask could write one, and the session
    /// acts on every mining message it is given, a coinbaser split among them. The C gateway
    /// accepts such a frame; the pool this gateway is released with never sends one, and
    /// refuses them in the other direction (`ServerChannel::decrypt`).
    pub fn decrypt(&mut self, header: FrameHeader, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let verify = self.pool_session_sign_pk.as_ref();
        match (header.is_encrypted_channel, header.is_encrypted_pubkey) {
            (true, false) => self.channel.decrypt(header, ciphertext, verify),
            (false, true) => {
                let plain =
                    open_sealed(&self.session_keys.box_pk, &self.session_keys.box_sk, ciphertext)?;
                strip_signature(plain, header, verify)
            }
            _ => Err(Error::Malformed(
                "pool message is not a channel-encrypted or sealed frame (plain or both flags)",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datum::server::accept;
    use crate::datum::server::tests::{client_with_generated_keys, server_read_hello};

    fn read_response(
        client: &mut ClientChannel,
        wire: &[u8],
        pool_sign_pk: &SignPublicKey,
    ) -> Result<(), Error> {
        let head: [u8; framing::HEADER_LEN] =
            wire.get(..framing::HEADER_LEN).ok_or(Error::Truncated)?.try_into().expect("4 bytes");
        let header = client.unmask_header(head);
        let body = wire
            .get(framing::HEADER_LEN..framing::HEADER_LEN + header.cmd_len as usize)
            .ok_or(Error::Truncated)?;
        client.read_handshake_response(header, body, pool_sign_pk)
    }

    #[test]
    fn client_and_server_complete_a_handshake_and_exchange_messages_both_ways() {
        let pool = KeyPairs::generate();
        let mut client = client_with_generated_keys(0x1122_3344);

        let wire = client.hello(&pool.box_pk, "v0.4.1-beta/deadbeef", ProtocolVersion::V1);
        let hello = server_read_hello(&wire, &pool).expect("parse hello");
        assert_eq!(hello.user_agent, "v0.4.1-beta/deadbeef");
        assert_eq!(hello.nk, 0x1122_3344);
        assert_eq!(hello.session, client.session_keys.public());

        let (response, mut session) = accept(hello, &pool, "RATUM Prime").unwrap();
        read_response(&mut client, &response, &pool.sign_pk).expect("read response");
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
        let mut client = client_with_generated_keys(9);
        let wire = client.hello(&pool.box_pk, "ua", ProtocolVersion::V1);
        let hello = server_read_hello(&wire, &pool).unwrap();
        let motd = "m".repeat(crate::datum::server::MAX_MOTD_LEN);
        let (response, _) = accept(hello, &pool, &motd).unwrap();
        read_response(&mut client, &response, &pool.sign_pk).unwrap();
        assert_eq!(client.motd(), motd);

        let mut client = client_with_generated_keys(9);
        let wire = client.hello(&pool.box_pk, "ua", ProtocolVersion::V1);
        let hello = server_read_hello(&wire, &pool).unwrap();
        let (response, _) = accept(hello, &pool, "").unwrap();
        read_response(&mut client, &response, &pool.sign_pk).unwrap();
        assert_eq!(client.motd(), "");
    }

    #[test]
    fn a_response_signed_by_another_pool_is_refused() {
        let pool = KeyPairs::generate();
        let other = KeyPairs::generate();
        let mut client = client_with_generated_keys(1);
        let wire = client.hello(&pool.box_pk, "ua", ProtocolVersion::V1);
        let hello = server_read_hello(&wire, &pool).unwrap();
        let (response, _) = accept(hello, &pool, "hi").unwrap();
        assert!(matches!(
            read_response(&mut client, &response, &other.sign_pk),
            Err(Error::BadSignature)
        ));
    }

    #[test]
    fn a_response_to_another_clients_hello_is_refused() {
        let pool = KeyPairs::generate();
        let mut client = client_with_generated_keys(1);
        let mut other = client_with_generated_keys(1);
        let _ = client.hello(&pool.box_pk, "ua", ProtocolVersion::V1);
        let wire = other.hello(&pool.box_pk, "ua", ProtocolVersion::V1);
        let hello = server_read_hello(&wire, &pool).unwrap();
        let (response, _) = accept(hello, &pool, "hi").unwrap();
        assert!(matches!(read_response(&mut client, &response, &pool.sign_pk), Err(Error::Unseal)));
    }

    /// Every cut of the body the pool sent, 0 to its length less one, reaches
    /// `read_handshake_response` on the client whose keys the response was sealed to, with the
    /// header the pool sent. A cut shorter than the seal's overhead is refused by the length
    /// check in `open_sealed` and a longer one by the seal's MAC; the length checks after the
    /// unseal are reached by the test below, which seals each prefix of the plaintext.
    #[test]
    fn a_truncated_response_is_refused_rather_than_panicking() {
        let pool = KeyPairs::generate();
        let mut client = client_with_generated_keys(1);
        let wire = client.hello(&pool.box_pk, "ua", ProtocolVersion::V1);
        let hello = server_read_hello(&wire, &pool).unwrap();
        let (response, _) = accept(hello, &pool, "hi").unwrap();
        let header = client.unmask_header(response[..framing::HEADER_LEN].try_into().unwrap());
        let body = &response[framing::HEADER_LEN..];
        assert_eq!(body.len(), header.cmd_len as usize);
        for cut in 0..body.len() {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                client.read_handshake_response(header, &body[..cut], &pool.sign_pk)
            }));
            let result = result.unwrap_or_else(|_| panic!("a body cut at {cut} panicked"));
            assert!(result.is_err(), "a body cut at {cut} of {} was accepted", body.len());
        }
        client
            .read_handshake_response(header, body, &pool.sign_pk)
            .expect("the whole body is read by the same client after every cut was refused");
        assert_eq!(client.motd(), "hi");
    }

    /// Each prefix of the signed plaintext, sealed to the client's session key, so the body
    /// opens and every length reaches the checks after the unseal: `split_signed` for a prefix
    /// shorter than a signature, `PublicKeys::split_from` for one shorter than the three key
    /// blocks, and the signature check for the rest.
    #[test]
    fn a_response_whose_sealed_body_is_short_is_refused_rather_than_panicking() {
        use crate::datum::channel::seal;
        let pool = KeyPairs::generate();
        let mut client = client_with_generated_keys(1);
        let _ = client.hello(&pool.box_pk, "ua", ProtocolVersion::V1);
        let header = FrameHeader {
            is_signed: true,
            is_encrypted_pubkey: true,
            proto_cmd: framing::cmd::HANDSHAKE_RESPONSE,
            ..Default::default()
        };
        let mut signed = Vec::new();
        signed.extend_from_slice(&client.long_term_keys.public().to_bytes());
        signed.extend_from_slice(&client.session_keys.public().to_bytes());
        signed.extend_from_slice(&KeyPairs::generate().public().to_bytes());
        signed.extend_from_slice(b"hi\0");
        crate::datum::channel::sign_append(&pool.sign_sk, &mut signed).unwrap();
        for cut in 0..signed.len() {
            let sealed = seal(&client.session_keys.box_pk, &signed[..cut]).unwrap();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                client.read_handshake_response(header, &sealed, &pool.sign_pk)
            }));
            let result = result.unwrap_or_else(|_| panic!("a plaintext cut at {cut} panicked"));
            assert!(result.is_err(), "a plaintext cut at {cut} of {} was accepted", signed.len());
        }
        let sealed = seal(&client.session_keys.box_pk, &signed).unwrap();
        client.read_handshake_response(header, &sealed, &pool.sign_pk).expect("the whole body");
    }

    #[test]
    fn encrypting_or_decrypting_before_the_handshake_is_an_error_not_a_panic() {
        let mut client = client_with_generated_keys(1);
        assert!(matches!(client.encrypt(framing::cmd::MINING, b"x"), Err(Error::NoChannel)));
        let header = FrameHeader { cmd_len: 4, is_encrypted_channel: true, ..Default::default() };
        assert!(matches!(client.decrypt(header, &[0u8; 32]), Err(Error::NoChannel)));
    }

    #[test]
    fn a_frame_neither_channel_encrypted_nor_sealed_is_refused_after_the_handshake() {
        let pool = KeyPairs::generate();
        let mut client = client_with_generated_keys(9);
        let wire = client.hello(&pool.box_pk, "ua", ProtocolVersion::V1);
        let hello = server_read_hello(&wire, &pool).unwrap();
        let (response, mut session) = accept(hello, &pool, "hi").unwrap();
        read_response(&mut client, &response, &pool.sign_pk).unwrap();

        let coinbaser = [crate::datum::messages::server_subcmd::COINBASER, 0, 0, 0];
        for proto_cmd in [framing::cmd::MINING, framing::cmd::HELLO_OR_PING, framing::cmd::INFO] {
            let plain = FrameHeader { cmd_len: 4, proto_cmd, ..Default::default() };
            assert!(
                matches!(client.decrypt(plain, &coinbaser), Err(Error::Malformed(_))),
                "a plain frame of command {proto_cmd}"
            );
            let both =
                FrameHeader { is_encrypted_channel: true, is_encrypted_pubkey: true, ..plain };
            assert!(
                matches!(client.decrypt(both, &coinbaser), Err(Error::Malformed(_))),
                "a frame of command {proto_cmd} carrying both encryption flags"
            );
        }
        let signed = FrameHeader {
            cmd_len: 70,
            is_signed: true,
            proto_cmd: framing::cmd::INFO,
            ..Default::default()
        };
        assert!(matches!(client.decrypt(signed, &[0u8; 70]), Err(Error::Malformed(_))));

        let wire = session.encrypt(framing::cmd::MINING, b"after", false).unwrap();
        let header = client.unmask_header(wire[..4].try_into().unwrap());
        assert_eq!(
            client.decrypt(header, &wire[4..]).unwrap(),
            b"after",
            "a refused frame does not advance the channel's nonce"
        );
    }

    #[test]
    fn the_channel_desynchronizes_if_a_frame_is_skipped() {
        let pool = KeyPairs::generate();
        let mut client = client_with_generated_keys(7);
        let wire = client.hello(&pool.box_pk, "ua", ProtocolVersion::V1);
        let hello = server_read_hello(&wire, &pool).unwrap();
        let (response, mut session) = accept(hello, &pool, "hi").unwrap();
        read_response(&mut client, &response, &pool.sign_pk).unwrap();

        let _skipped = session.encrypt(framing::cmd::MINING, b"one", false).unwrap();
        let second = session.encrypt(framing::cmd::MINING, b"two", false).unwrap();
        let h = client.unmask_header(second[..4].try_into().unwrap());
        assert!(client.decrypt(h, &second[4..]).is_err(), "a skipped frame must not decrypt");
    }
}
