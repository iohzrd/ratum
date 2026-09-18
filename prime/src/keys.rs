//! The pool's long-term key pair, generated on first start into a file only its owner can read.

use log::info;
use ratum::datum::keys::{KEY_PAIRS_LEN, KeyPairs};
use std::io;
use std::path::Path;

pub fn load_or_create_keys(path: &Path) -> io::Result<KeyPairs> {
    if !path.exists() {
        let keys = KeyPairs::generate();
        write_private(path, hex::encode(keys.to_bytes()).as_bytes())?;
        info!("generated new pool keys at {}", path.display());
        return Ok(keys);
    }
    let text = std::fs::read_to_string(path)?;
    let raw =
        hex::decode(text.trim()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    KeyPairs::from_bytes(&raw).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("key file must decode to {} bytes of hex", KEY_PAIRS_LEN),
        )
    })
}

#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)
}

#[cfg(not(unix))]
fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    std::fs::write(path, data)
}
