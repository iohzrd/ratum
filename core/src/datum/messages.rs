//! The messages a DATUM connection carries, and the pieces every one of them is built from: the
//! subcommand byte a message opens with, the 0xFE terminator it ends with, and the subcommand
//! numbers of each direction.

pub mod abw;
pub mod coinbaser;
pub mod config;
pub mod migration;
pub mod share;
pub mod share_response;
pub mod validation;

use crate::reader::ByteReader;

pub(crate) const STRUCT_END: u8 = 0xFE;

/// A reader over `data` past its first byte, which must be `subcmd`: every message starts with
/// the subcommand its receiver dispatched it on.
fn open_message(data: &[u8], subcmd: u8) -> Result<ByteReader<'_>, Error> {
    let mut c = ByteReader::new(data);
    let got = c.u8("subcommand")?;
    if got != subcmd {
        return Err(Error::WrongMessage { want: subcmd, got });
    }
    Ok(c)
}

/// Reads the 0xFE terminator that ends a message; the bytes after it are not read.
fn read_terminator(c: &mut ByteReader<'_>) -> Result<(), Error> {
    if c.u8("terminator")? != STRUCT_END {
        return Err(Error::BadTerminator);
    }
    Ok(())
}

/// Reads the terminator and refuses a message with bytes after it.
fn read_final_terminator(c: &mut ByteReader<'_>) -> Result<(), Error> {
    read_terminator(c)?;
    if !c.at_end() {
        return Err(Error::Malformed("bytes after the terminator"));
    }
    Ok(())
}

/// What the pool sends. Validation is not here: its subcommand is the same byte in both
/// directions, and `validation::SUBCMD` holds it.
pub mod server_subcmd {
    pub const CONFIG: u8 = 0x99;
    pub const COINBASER: u8 = 0x11;
    pub const SHARE_RESPONSE: u8 = 0x8F;
    pub const BLOCKNOTIFY: u8 = 0xF9;
    pub const MIGRATION: u8 = 0xA4;
}

pub mod client_subcmd {
    pub const COINBASER_REQUEST: u8 = 0x10;
    pub const SUBMIT_POW: u8 = 0x27;
}

/// What refuses a message on either side: the encoder's field limits and the decoder's
/// shape checks; a decoder names the field a short message ends in. One enum serves every
/// message type, so a caller that handles several decoders handles one error.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("truncated at {0}")]
    Truncated(#[from] crate::reader::Truncated),
    #[error("unknown version {0}")]
    BadVersion(u8),
    #[error("unknown flags {0:#04x}")]
    BadFlags(u8),
    #[error("unknown status {0:#04x}")]
    BadStatus(u8),
    #[error("ABW slot {0} out of range")]
    BadSlot(u8),
    #[error("expected message {want:#04x}, got {got:#04x}")]
    WrongMessage { want: u8, got: u8 },
    #[error("missing 0xFE terminator")]
    BadTerminator,
    #[error("{0}")]
    Malformed(&'static str),
    #[error("{field} too long: {len} bytes")]
    TooLong { field: &'static str, len: usize },
    #[error("{field} length {len} is out of range")]
    OutOfRange { field: &'static str, len: usize },
    #[error("min difficulty {0} is not a power of two")]
    MinDifficultyNotPowerOfTwo(u64),
    #[error("prime id {0} does not fit the version 1 configuration's 32 bits")]
    PrimeIdTooWide(u64),
    #[error("payout split totals {total} sats, exceeding the job's {value}")]
    SplitExceedsValue { total: u64, value: u64 },
    #[error("extranonce size {0}, expected 12")]
    BadExtranonceSize(u8),
    #[error("username not terminated")]
    BadUsername,
    #[error("merkle branch count {0} too large")]
    BadMerkleCount(u8),
    #[error("unknown section marker {0:#04x}")]
    UnknownSection(u8),
    #[error("malformed BLAKE2b section")]
    BadBlake2bSection,
    #[error("no BLAKE2b section")]
    MissingBlake2bSection,
}

pub const BLOCKNOTIFY_MESSAGE: [u8; 1] = [server_subcmd::BLOCKNOTIFY];
