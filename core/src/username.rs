//! The miner username both sides read the same way: `<address>[.<worker>]`. The gateway decides
//! from the address whether a coinbase output can pay it, and the pool credits the share to that
//! same address, so the two must split a username identically or the gateway accepts work the pool
//! refuses.

/// The address at the start of `username` and the worker name after it, with its leading `.`,
/// or empty when there is none.
pub fn split_address_worker(username: &str) -> (&str, &str) {
    username.split_at(username.find('.').unwrap_or(username.len()))
}

/// The address a username's shares are credited to.
pub fn address_of(username: &str) -> &str {
    split_address_worker(username).0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_username_splits_at_its_first_dot() {
        assert_eq!(split_address_worker("bc1qexample.worker1"), ("bc1qexample", ".worker1"));
        assert_eq!(split_address_worker("bc1qexample"), ("bc1qexample", ""));
        assert_eq!(split_address_worker("bc1q.a.b"), ("bc1q", ".a.b"), "the first dot alone");
        assert_eq!(split_address_worker(""), ("", ""));
        assert_eq!(split_address_worker(".worker"), ("", ".worker"), "no address");
        assert_eq!(address_of("bc1qexample.worker1"), "bc1qexample");
    }
}
