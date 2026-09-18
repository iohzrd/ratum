//! The pool's end of the handshake: it opens the gateway's sealed hello, answers with a fresh
//! session key pair signed by the pool's long-term key, and holds the channel every later frame
//! runs through.

use super::channel::{Channel, Error, open_sealed, seal_signed, split_signed, verify};
use super::framing::{self, FrameHeader, HeaderKeys, SessionNonces};
use super::handshake::{
    DRS_FLAG_AT, DRS_MARKER, DRS_TOKEN_AT, ProtocolVersion, RESUME_TOKEN_LEN, ResumeToken,
};
use super::keys::{KeyPairs, PUBLIC_KEYS_LEN, PublicKeys};
use super::messages::STRUCT_END;
use dryoc::classic::crypto_box::crypto_box_beforenm;
use dryoc::classic::crypto_sign::SecretKey as SignSecretKey;

const MAX_USER_AGENT_LEN: usize = 256;
const AFTER_UA_LEN: usize = 1 + size_of::<u32>();
pub(crate) const MAX_MOTD_LEN: usize = 511;

#[derive(Clone, Debug)]
pub struct Hello {
    pub client: PublicKeys,
    pub session: PublicKeys,
    pub user_agent: String,
    pub nk: u32,
    pub protocol_version: ProtocolVersion,
}

pub fn open_hello(header: FrameHeader, payload: &[u8], pool: &KeyPairs) -> Result<Hello, Error> {
    if header.proto_cmd != framing::cmd::HELLO_OR_PING
        || !header.is_signed
        || !header.is_encrypted_pubkey
        || header.is_encrypted_channel
    {
        return Err(Error::BadHeader(header));
    }
    let plain = open_sealed(&pool.box_pk, &pool.box_sk, payload)?;
    let (signed, sig) = split_signed(&plain)?;
    let (client, rest) = PublicKeys::split_from(signed).ok_or(Error::Truncated)?;
    let (session, rest) = PublicKeys::split_from(rest).ok_or(Error::Truncated)?;
    verify(&sig, signed, &client.sign_pk)?;

    let nul = rest.iter().position(|&b| b == 0).ok_or(Error::Malformed("no UA terminator"))?;
    let user_agent = String::from_utf8_lossy(&rest[..nul.min(MAX_USER_AGENT_LEN)]).into_owned();
    let after = &rest[nul + 1..];
    if after.len() < AFTER_UA_LEN {
        return Err(Error::Truncated);
    }
    if after[0] != STRUCT_END {
        return Err(Error::Malformed("no 0xFE after user agent"));
    }
    let nk = u32::from_le_bytes(after[1..AFTER_UA_LEN].try_into().expect("AFTER_UA_LEN - 1 bytes"));

    let tail = &after[AFTER_UA_LEN..];
    let protocol_version = if tail.len() > DRS_FLAG_AT && tail[..DRS_FLAG_AT] == DRS_MARKER {
        let resume = if tail[DRS_FLAG_AT] != 0 {
            let token: ResumeToken = tail
                .get(DRS_TOKEN_AT..DRS_TOKEN_AT + RESUME_TOKEN_LEN)
                .ok_or(Error::Malformed("DRS flag set without a token"))?
                .try_into()
                .expect("length checked");
            Some(token)
        } else {
            None
        };
        ProtocolVersion::V3 { resume }
    } else {
        ProtocolVersion::V1
    };

    Ok(Hello { client, session, user_agent, nk, protocol_version })
}

pub struct ServerChannel {
    channel: Channel,
    session_sign_sk: SignSecretKey,
    hello: Hello,
}

impl ServerChannel {
    pub fn encrypt(&mut self, proto_cmd: u8, payload: &[u8], sign: bool) -> Result<Vec<u8>, Error> {
        self.channel.encrypt(proto_cmd, payload, sign.then_some(&self.session_sign_sk))
    }

    pub fn unmask_header(&mut self, bytes: [u8; framing::HEADER_LEN]) -> FrameHeader {
        self.channel.unmask_header(bytes)
    }

    pub fn decrypt(&mut self, header: FrameHeader, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        if !header.is_encrypted_channel || header.is_encrypted_pubkey {
            return Err(Error::Malformed(
                "client message is not a channel-encrypted frame (sealed or plain)",
            ));
        }
        self.channel.decrypt(header, ciphertext, Some(&self.hello.session.sign_pk))
    }
}

pub fn accept(
    hello: Hello,
    pool: &KeyPairs,
    motd: &str,
) -> Result<(Vec<u8>, ServerChannel), Error> {
    let session_keys = KeyPairs::generate();

    let mut body = Vec::with_capacity(3 * PUBLIC_KEYS_LEN + motd.len() + 1);
    body.extend_from_slice(&hello.client.to_bytes());
    body.extend_from_slice(&hello.session.to_bytes());
    body.extend_from_slice(&session_keys.public().to_bytes());
    let motd_bytes = motd.as_bytes();
    let motd_bytes = &motd_bytes[..motd_bytes.len().min(MAX_MOTD_LEN)];
    body.extend_from_slice(motd_bytes);
    body.push(0);

    let sealed = seal_signed(&pool.sign_sk, &hello.session.box_pk, body)?;
    if sealed.len() > framing::MAX_CMD_LEN {
        return Err(Error::TooLarge(sealed.len()));
    }

    let precomp = crypto_box_beforenm(&hello.session.box_pk, &session_keys.box_sk)
        .map_err(|_| Error::Malformed("bad session key"))?;
    let keys = HeaderKeys::from_nk(hello.nk);
    let nonces = SessionNonces::derive(hello.nk, &hello.session.sign_pk);
    let mut channel = Channel::server(keys, nonces, precomp);

    let header = FrameHeader {
        is_signed: true,
        is_encrypted_pubkey: true,
        proto_cmd: framing::cmd::HANDSHAKE_RESPONSE,
        ..Default::default()
    };
    let out = channel.frame(header, &sealed);
    Ok((out, ServerChannel { channel, session_sign_sk: session_keys.sign_sk, hello }))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::datum::client::ClientChannel;
    use crate::datum::framing::HeaderKeyRatchet;

    pub(crate) fn client_with_generated_keys(nk: u32) -> ClientChannel {
        ClientChannel::with_key_pairs(KeyPairs::generate(), KeyPairs::generate(), nk)
    }

    pub(crate) fn server_read_hello(wire: &[u8], pool: &KeyPairs) -> Result<Hello, Error> {
        let mut rx = HeaderKeyRatchet::initial();
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
        body.extend_from_slice(&long_term.public().to_bytes());
        body.extend_from_slice(&session.public().to_bytes());
        body.extend_from_slice(b"v0.4.1-beta/deadbeef");
        body.push(0);
        body.push(STRUCT_END);
        body.extend_from_slice(&nk.to_le_bytes());
        body.extend_from_slice(&[0xAB; 17]);
        let sealed = seal_signed(&long_term.sign_sk, &pool.box_pk, body).unwrap();

        let header = FrameHeader {
            cmd_len: sealed.len() as u32,
            is_signed: true,
            is_encrypted_pubkey: true,
            proto_cmd: framing::cmd::HELLO_OR_PING,
            ..Default::default()
        };
        let hello = open_hello(header, &sealed, &pool).expect("pad bytes are not checked");
        assert_eq!(hello.user_agent, "v0.4.1-beta/deadbeef");
        assert_eq!(hello.nk, nk);
        assert_eq!(hello.session, session.public());
    }

    #[test]
    fn rejects_hello_sealed_to_another_pool() {
        let pool = KeyPairs::generate();
        let other = KeyPairs::generate();
        let mut client = client_with_generated_keys(7);
        let wire = client.hello(&other.box_pk, "v0.4.1-beta", ProtocolVersion::V1);
        assert!(matches!(server_read_hello(&wire, &pool), Err(Error::Unseal)));
    }

    #[test]
    fn rejects_hello_whose_sealed_bytes_are_altered() {
        let pool = KeyPairs::generate();
        let mut client = client_with_generated_keys(7);
        let mut bad = client.hello(&pool.box_pk, "v0.4.1-beta", ProtocolVersion::V1);
        let n = bad.len();
        bad[n - 1] ^= 0x01;
        assert!(matches!(server_read_hello(&bad, &pool), Err(Error::Unseal)));
    }

    #[test]
    fn rejects_wrong_command() {
        let pool = KeyPairs::generate();
        let header = FrameHeader {
            cmd_len: 100,
            is_signed: true,
            is_encrypted_pubkey: true,
            proto_cmd: framing::cmd::MINING,
            ..Default::default()
        };
        assert!(matches!(open_hello(header, &[0u8; 100], &pool), Err(Error::BadHeader(_))));
    }
}
