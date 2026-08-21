//! A stand-in DATUM gateway: the client end of one connection to the pool.

use super::*;
use ratum::datum::client::Client;
use ratum::datum::framing::{self, Header};
use ratum::datum::handshake::KeyPairs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// A stand-in for the DATUM gateway: the client end of one connection to the pool.
pub struct Gateway {
    stream: TcpStream,
    client: Client,
    pool_sign_pk: [u8; 32],
}

impl Gateway {
    pub fn connect(addr: SocketAddr, pool_sign_pk: [u8; 32], pool_box_pk: [u8; 32]) -> Self {
        Gateway::connect_as(addr, pool_sign_pk, pool_box_pk, "v0.4.1-beta/test", 0x1234_5678)
    }

    pub fn connect_as(
        addr: SocketAddr,
        pool_sign_pk: [u8; 32],
        pool_box_pk: [u8; 32],
        user_agent: &str,
        nk: u32,
    ) -> Self {
        let stream = TcpStream::connect(addr).expect("connect to the pool");
        stream.set_read_timeout(Some(TIMEOUT)).expect("read timeout");
        stream.set_write_timeout(Some(TIMEOUT)).expect("write timeout");
        let client = Client::with_key_pairs(KeyPairs::generate(), KeyPairs::generate(), nk);

        let mut gateway = Gateway { stream, client, pool_sign_pk };
        let hello = gateway.client.hello(&pool_box_pk, user_agent);
        gateway.stream.write_all(&hello).expect("send hello");
        gateway.stream.flush().expect("flush hello");

        // Read the response frame without advancing the client's ratchet: the first
        // server-to-client header is masked with the unadvanced key derived from nk, and
        // `read_handshake_response` unmasks that header itself.
        let mut head = [0u8; 4];
        gateway.stream.read_exact(&mut head).expect("handshake frame header");
        let key = framing::HeaderKeys::from_nk(nk).server_to_client;
        let peeked = Header::from_bytes((u32::from_le_bytes(head) ^ key).to_le_bytes());
        let mut body = vec![0u8; peeked.cmd_len as usize];
        gateway.stream.read_exact(&mut body).expect("handshake frame body");

        let mut frame = Vec::with_capacity(4 + body.len());
        frame.extend_from_slice(&head);
        frame.extend_from_slice(&body);
        gateway
            .client
            .read_handshake_response(&frame, &gateway.pool_sign_pk)
            .expect("handshake response");
        gateway
    }

    pub fn motd(&self) -> &str {
        self.client.motd()
    }

    /// Read one channel message: its header and its decrypted payload.
    pub fn recv(&mut self) -> (Header, Vec<u8>) {
        let mut head = [0u8; 4];
        self.stream.read_exact(&mut head).expect("frame header");
        let header = self.client.unmask_header(head);
        let mut body = vec![0u8; header.cmd_len as usize];
        self.stream.read_exact(&mut body).expect("frame body");
        let payload = self.client.decrypt(header, &body).expect("decrypt");
        (header, payload)
    }

    /// Read messages until one starts with `marker`, returning it. Any message received
    /// before it is returned too, so a test can assert on what it skipped.
    pub fn recv_until(&mut self, marker: u8) -> (Vec<u8>, Vec<Vec<u8>>) {
        let mut skipped = Vec::new();
        for _ in 0..64 {
            let (_, payload) = self.recv();
            if payload.first() == Some(&marker) {
                return (payload, skipped);
            }
            skipped.push(payload);
        }
        panic!("never received a message starting {marker:#04x}; received {skipped:?}");
    }

    pub fn send(&mut self, proto_cmd: u8, payload: &[u8]) {
        let wire = self.client.encrypt(proto_cmd, payload).expect("encrypt");
        self.stream.write_all(&wire).expect("send");
        self.stream.flush().expect("flush");
    }

    pub fn send_mining(&mut self, payload: &[u8]) {
        self.send(framing::cmd::MINING, payload);
    }

    pub fn set_read_timeout(&self, d: Option<Duration>) {
        self.stream.set_read_timeout(d).expect("set read timeout");
    }

    /// Read one message if the pool sends one within `timeout`.
    pub fn try_recv(&mut self, timeout: Duration) -> Option<(Header, Vec<u8>)> {
        self.set_read_timeout(Some(timeout));
        let mut head = [0u8; 4];
        let got = self.stream.read_exact(&mut head);
        self.set_read_timeout(Some(TIMEOUT));
        got.ok()?;
        let header = self.client.unmask_header(head);
        let mut body = vec![0u8; header.cmd_len as usize];
        self.stream.read_exact(&mut body).expect("frame body");
        let payload = self.client.decrypt(header, &body).expect("decrypt");
        Some((header, payload))
    }

    /// True if no message arrived from the pool within `duration`.
    pub fn sent_nothing_for(&mut self, duration: Duration) -> bool {
        self.try_recv(duration).is_none()
    }

    /// Read for `duration`, and report whether any message started with `marker`. Messages
    /// the pool sends on its own schedule, such as a blocknotify, do not count.
    pub fn received_no(&mut self, marker: u8, duration: Duration) -> bool {
        let deadline = Instant::now() + duration;
        while Instant::now() < deadline {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.try_recv(left) {
                Some((_, payload)) if payload.first() == Some(&marker) => return false,
                Some(_) => continue,
                None => return true,
            }
        }
        true
    }
}
