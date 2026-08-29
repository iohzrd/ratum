//! The pool side of RATUM that is not protocol: the command line and file configuration,
//! the share ledger, and share verification. The `ratum-prime` binary in `main.rs` and the
//! integration tests in `tests/` are built on these; the wire protocol, header and target
//! code they use is the `ratum` library.

pub mod config;
pub mod ledger;
pub mod verify;
