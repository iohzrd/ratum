//! The miner username both sides read the same way: `<address>[.<worker>]`. The gateway decides
//! from the address whether a coinbase output can pay it, and the pool credits the share to that
//! same address (an uppercase bech32 address in lowercase), so the two must split a username
//! identically or the gateway accepts work the pool refuses.

/// The address at the start of `username` and the worker name after it, with its leading `.`,
/// or empty when there is none.
pub fn split_address_worker(username: &str) -> (&str, &str) {
    username.split_at(username.find('.').unwrap_or(username.len()))
}

/// The address at the start of a username, as the miner wrote it. The gateway checks this
/// string; the pool credits `identity_of`.
pub fn address_of(username: &str) -> &str {
    split_address_worker(username).0
}

/// The identity a username's shares are credited to: its address in the form
/// `address::canonical` gives, so a bech32 address written in uppercase and the same address
/// in lowercase are one identity, as they pay one script.
pub fn identity_of(username: &str) -> std::borrow::Cow<'_, str> {
    crate::bitcoin::address::canonical(address_of(username))
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

    #[test]
    fn the_identity_is_the_address_with_an_uppercase_bech32_address_lowercased() {
        const LOWER: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let upper = LOWER.to_ascii_uppercase();
        assert_eq!(identity_of(&format!("{upper}.RIG1")), LOWER, "the worker is not part of it");
        assert_eq!(identity_of(&format!("{LOWER}.rig2")), LOWER);
        assert_eq!(address_of(&format!("{upper}.RIG1")), upper, "what the gateway checks is kept");
        let base58 = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2.rig";
        assert_eq!(identity_of(base58), "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
    }
}
