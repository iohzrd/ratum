use crate::address;

pub type Modifiers = Vec<(String, Vec<(String, f64)>)>;

pub fn address_of(username: &str) -> &str {
    let end = username.find(['.', '~']).unwrap_or(username.len());
    &username[..end]
}

pub fn is_payable(username: &str) -> bool {
    address::is_valid(address_of(username))
}

pub const SELECTOR_SPACE: f64 = 65536.0;
pub const SELECTOR_MAX: i64 = u16::MAX as i64;

pub fn apply_modifier(
    modifiers: &Modifiers,
    pool_address: &str,
    username: &str,
    hash: &[u8; 32],
) -> Option<String> {
    let tilde = username.find('~')?;
    let modname = &username[tilde + 1..];
    let base = &username[..tilde];
    let ranges = &modifiers.iter().find(|(name, _)| name == modname)?.1;
    let selector = i64::from(u16::from_le_bytes([hash[31], hash[30]]));
    let worker = base.find('.').map_or("", |d| &base[d..]);
    let mut sum = 0f64;
    for (addr, proportion) in ranges {
        sum += proportion.max(0.0);
        let end = ((sum * SELECTOR_SPACE).ceil() as i64 - 1).min(SELECTOR_MAX);
        if selector <= end {
            return Some(if addr.is_empty() {
                base.to_string()
            } else {
                format!("{addr}{worker}")
            });
        }
    }
    Some(pool_address.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_forms() {
        assert!(is_payable("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
        assert!(is_payable("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4.worker"));
        assert!(is_payable("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4~mod"));
        assert!(!is_payable("lazyminer.worker"));
        assert!(!is_payable(".worker"));
        assert_eq!(address_of("a.b~c"), "a");
    }

    fn hash_with_selector(rnd: u16) -> [u8; 32] {
        let mut h = [0u8; 32];
        let b = rnd.to_le_bytes();
        h[31] = b[0];
        h[30] = b[1];
        h
    }

    fn modifiers() -> Modifiers {
        vec![("split".to_string(), vec![("bc1qfirst".to_string(), 0.3), (String::new(), 0.5)])]
    }

    #[test]
    fn the_selector_is_the_low_word_of_the_hash_and_picks_the_range_in_file_order() {
        let m = modifiers();
        let first = apply_modifier(&m, "bc1qpool", "bc1qme.rig~split", &hash_with_selector(0x0001));
        assert_eq!(first.as_deref(), Some("bc1qfirst.rig"));
        let edge = apply_modifier(&m, "bc1qpool", "bc1qme.rig~split", &hash_with_selector(0x4ccc));
        assert_eq!(edge.as_deref(), Some("bc1qfirst.rig"));
        let own = apply_modifier(&m, "bc1qpool", "bc1qme.rig~split", &hash_with_selector(0x4ccd));
        assert_eq!(own.as_deref(), Some("bc1qme.rig"));
        let own = apply_modifier(&m, "bc1qpool", "bc1qme~split", &hash_with_selector(0xcccc));
        assert_eq!(own.as_deref(), Some("bc1qme"));
        let rest = apply_modifier(&m, "bc1qpool", "bc1qme.rig~split", &hash_with_selector(0xcccd));
        assert_eq!(rest.as_deref(), Some("bc1qpool"));
    }

    #[test]
    fn leading_zeros_do_not_decide_it() {
        let m = modifiers();
        let mut h = hash_with_selector(0x0100);
        h[0] = 0xff;
        h[1] = 0xff;
        assert_eq!(
            apply_modifier(&m, "bc1qpool", "bc1qme~split", &h).as_deref(),
            Some("bc1qfirst")
        );
    }

    #[test]
    fn no_modifier_or_an_unknown_one_leaves_the_username_alone() {
        let m = modifiers();
        assert_eq!(apply_modifier(&m, "p", "bc1qme.rig", &[0; 32]), None);
        assert_eq!(apply_modifier(&m, "p", "bc1qme.rig~other", &[0; 32]), None);
    }
}
