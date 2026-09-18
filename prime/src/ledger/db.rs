//! The redb plumbing the share table and the block records share: opening a database, running a
//! durable write transaction, reporting a store error as an `io::Error`, and the separator the
//! packed rows put between a name and the bytes after it.

use redb::{Database, Durability};
use std::io;
use std::path::Path;
use std::sync::Arc;

/// What a packed row puts between a name of any length and the field after it, since neither
/// an identity nor a coinbase tag may hold a zero byte.
pub(super) const NAME_SEPARATOR: u8 = 0x00;

pub(super) fn split_at_separator(rest: &[u8]) -> (&[u8], &[u8]) {
    match rest.iter().position(|&b| b == NAME_SEPARATOR) {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, [].as_slice()),
    }
}

pub(super) trait DbResult<T> {
    fn db(self) -> io::Result<T>;
}

impl<T, E: std::fmt::Display> DbResult<T> for Result<T, E> {
    fn db(self) -> io::Result<T> {
        self.map_err(|e| io::Error::other(e.to_string()))
    }
}

pub(super) fn create_database(path: &Path) -> io::Result<Arc<Database>> {
    Database::create(path).db().map(Arc::new)
}

/// Runs `f` in a write transaction committed at `Durability::Immediate`, so a row is on disk
/// before the caller is told it was written.
pub(super) fn write<T>(
    db: &Database,
    f: impl FnOnce(&redb::WriteTransaction) -> io::Result<T>,
) -> io::Result<T> {
    let mut w = db.begin_write().db()?;
    w.set_durability(Durability::Immediate).db()?;
    let out = f(&w)?;
    w.commit().db()?;
    Ok(out)
}
