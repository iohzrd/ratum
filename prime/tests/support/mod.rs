//! Test harness: a stand-in bitcoin node (`node`), a wrapper that starts the `ratum-prime`
//! binary and captures its output (`pool`), a stand-in gateway (`gateway`), and the work they
//! exchange (`work`).
//!
//! The tests that use this run the release binary itself (same argument parsing, same
//! threads, same sockets), so what they cover is the program, not a re-implementation of
//! it inside a test.

#![allow(dead_code)]

pub mod gateway;
pub mod node;
pub mod pool;
pub mod work;

// Each integration test crate compiles this harness and uses a subset of it.
#[allow(unused_imports)]
pub use gateway::Gateway;
#[allow(unused_imports)]
pub use node::{FakeNode, NodeState, script_for_address};
#[allow(unused_imports)]
pub use pool::{Pool, PoolArgs, printed, run_pool};

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

pub const POLL: Duration = Duration::from_millis(10);
pub const TIMEOUT: Duration = Duration::from_secs(20);

pub use ratum::lock;

/// A directory removed when this value is dropped, so a failed test leaves no state behind for
/// the next.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "ratum-test-{tag}-{}-{n}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("make temp dir");
        TempDir(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
