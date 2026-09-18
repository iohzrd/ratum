//! The redb plumbing the share table and the block records share: opening a database, running a
//! durable write transaction, reporting a store error as an `io::Error`, and the separator the
//! packed rows put between a name and the bytes after it.

use redb::{Builder, Database, Durability};
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

/// The memory redb may hold pages of the file in, in place of its 1 GiB default, which a file
/// read back at startup fills. The pool appends at the end of the share table and otherwise
/// scans it in order; read-back time and insert rate measured the same from 16 MiB to 1 GiB.
const PAGE_CACHE_BYTES: usize = 64 << 20;

fn builder() -> Builder {
    let mut b = Builder::new();
    b.set_cache_size(PAGE_CACHE_BYTES);
    b
}

pub(super) fn create_database(path: &Path) -> io::Result<Arc<Database>> {
    builder().create(path).db().map(Arc::new)
}

/// Opens an existing database, repairing a file a pool stopped by a signal did not close.
pub(super) fn open_database(path: &Path) -> io::Result<Database> {
    builder().open(path).db()
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
