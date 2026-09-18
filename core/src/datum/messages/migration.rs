//! The pool's migration request (0xA4), naming another pool to connect to or asking for a return to
//! the configured one. This crate decodes it; acting on it is left to the caller.

use super::{Error, open_message, read_final_terminator, server_subcmd};
use crate::datum::keys::PublicKeys;

pub(crate) const MIGRATION_REVISION: u8 = 0;
pub(crate) const MIGRATION_ACTION_REDIRECT: u8 = 0;
pub(crate) const MIGRATION_ACTION_RETURN_HOME: u8 = 1;
pub(crate) const MAX_MIGRATION_HOST_LEN: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MigrationRequest {
    Redirect(MigrationTarget),
    ReturnHome,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationTarget {
    pub host: String,
    pub port: u16,
    pub pubkey: PublicKeys,
}

impl MigrationRequest {
    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut c = open_message(data, server_subcmd::MIGRATION)?;
        let revision = c.u8("revision")?;
        if revision != MIGRATION_REVISION {
            return Err(Error::BadVersion(revision));
        }
        let request = match c.u8("action")? {
            MIGRATION_ACTION_RETURN_HOME => Self::ReturnHome,
            MIGRATION_ACTION_REDIRECT => {
                let host_len = c.u16("host length")? as usize;
                if host_len == 0 || host_len >= MAX_MIGRATION_HOST_LEN {
                    return Err(Error::OutOfRange { field: "host", len: host_len });
                }
                let host = c.take(host_len, "host")?;
                if host.contains(&0) {
                    return Err(Error::Malformed("host holds a NUL byte"));
                }
                let host = String::from_utf8_lossy(host).into_owned();
                let port = c.u16("port")?;
                if port == 0 {
                    return Err(Error::Malformed("port is 0"));
                }
                let pubkey = PublicKeys::from_bytes(&c.arr("pubkey")?);
                Self::Redirect(MigrationTarget { host, port, pubkey })
            }
            _ => return Err(Error::Malformed("unknown migration action")),
        };
        read_final_terminator(&mut c)?;
        Ok(request)
    }
}
