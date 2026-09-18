//! The DATUM protocol: the frames a connection is read and written in, the encrypted channel they
//! carry once the handshake completes, and the messages inside it.

pub mod bulk;
pub mod channel;
pub mod client;
pub(crate) mod codes;
pub mod coinbase;
pub mod framing;
pub mod handshake;
pub mod keys;
pub mod messages;
pub mod server;
