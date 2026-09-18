//! The stratum username: the address the pool credits it to, and the `~name` suffix that sends a
//! proportion of a miner's shares to other addresses.

use crate::config::DatumConfig;
use ratum::bitcoin::address;
use ratum::datum::messages::share::MAX_USERNAME_LEN;

#[derive(Clone, Debug, PartialEq)]
pub struct UsernameModifier {
    pub name: String,
    pub ranges: Vec<ModifierRange>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ModifierRange {
    pub address: String,
    pub proportion: f64,
}

/// A stratum username read as `<address>[.<worker>][~<modifier>]`: the address the pool
/// credits its shares to, the worker name that follows it (with its leading `.`, or empty),
/// and the modifier a `~name` suffix names. A suffix naming no configured modifier is not a
/// suffix at all: it stays part of the address, and so reaches the pool unchanged.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Parsed<'a, 'm> {
    pub address: &'a str,
    pub worker: &'a str,
    pub modifier: Option<&'m UsernameModifier>,
}

pub fn parse<'a, 'm>(username: &'a str, modifiers: &'m [UsernameModifier]) -> Parsed<'a, 'm> {
    let named = username
        .split_once('~')
        .and_then(|(base, name)| Some((base, modifiers.iter().find(|m| m.name == name)?)));
    let (base, modifier) = match named {
        Some((base, m)) => (base, Some(m)),
        None => (username, None),
    };
    let (address, worker) = ratum::username::split_address_worker(base);
    Parsed { address, worker, modifier }
}

/// The address the pool credits a username's shares to.
pub fn address_of<'a>(username: &'a str, modifiers: &[UsernameModifier]) -> &'a str {
    parse(username, modifiers).address
}

/// Whether the username's address (`address_of`) is one a coinbase output can pay, with the
/// address prefixes of any chain: this check does not read the node's chain.
pub fn is_payable(username: &str, modifiers: &[UsernameModifier]) -> bool {
    address::is_valid(address_of(username, modifiers), None)
}

const SELECTOR_SPACE: f64 = 65536.0;
const SELECTOR_MAX: i64 = u16::MAX as i64;

/// The highest selector value a range reaches, given the proportions up to and including it.
fn range_end(cumulative: f64) -> i64 {
    ((cumulative * SELECTOR_SPACE).ceil() as i64 - 1).min(SELECTOR_MAX)
}

/// The proportion of a modifier's shares its ranges leave to the gateway's own address; none
/// when they cover every selector value between them.
pub fn uncovered_share(m: &UsernameModifier) -> Option<f64> {
    let mut sum = 0f64;
    for range in &m.ranges {
        sum += range.proportion;
        if range_end(sum) >= SELECTOR_MAX {
            return None;
        }
    }
    Some(1.0 - sum)
}

/// The address `username`'s `~name` suffix sends this share to, chosen by the selector the
/// share's hash carries; none when the username names no configured modifier.
pub fn apply_modifier(
    modifiers: &[UsernameModifier],
    pool_address: &str,
    username: &str,
    hash: &[u8; 32],
) -> Option<String> {
    let Parsed { address, worker, modifier } = parse(username, modifiers);
    let selector = i64::from(u16::from_le_bytes([hash[31], hash[30]]));
    let mut sum = 0f64;
    for range in &modifier?.ranges {
        sum += range.proportion.max(0.0);
        if selector <= range_end(sum) {
            let paid = if range.address.is_empty() { address } else { &range.address };
            return Some(format!("{paid}{worker}"));
        }
    }
    Some(pool_address.to_string())
}

/// The username a share carries to the pool: the miner's own, the gateway's address with the
/// miner's worker name, or the gateway's address alone, as `datum.pool_pass_*` select, cut to
/// the protocol's length limit on a character boundary.
pub fn for_wire(d: &DatumConfig, pool_address: &str, username: &str) -> String {
    let full = if (!d.pool_pass_full_users && !d.pool_pass_workers) || username.is_empty() {
        pool_address.to_string()
    } else if d.pool_pass_full_users && !username.starts_with('.') {
        username.to_string()
    } else {
        let dot = if username.starts_with('.') { "" } else { "." };
        format!("{pool_address}{dot}{username}")
    };
    let mut end = full.len().min(MAX_USERNAME_LEN);
    while !full.is_char_boundary(end) {
        end -= 1;
    }
    full[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_forms() {
        const ADDRESS: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let m = modifiers();
        assert!(is_payable(ADDRESS, &m));
        assert!(is_payable(&format!("{ADDRESS}.worker"), &m));
        assert!(is_payable(&format!("{ADDRESS}~split"), &m));
        assert!(is_payable(&format!("{ADDRESS}.worker~split"), &m));
        assert!(!is_payable("lazyminer.worker", &m));
        assert!(!is_payable(".worker", &m));
        assert_eq!(address_of("a.b~split", &m), "a");
    }

    #[test]
    fn a_suffix_naming_no_modifier_stays_in_the_address_the_pool_reads() {
        const ADDRESS: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let m = modifiers();
        assert_eq!(address_of(&format!("{ADDRESS}~typo"), &m), format!("{ADDRESS}~typo"));
        assert!(!is_payable(&format!("{ADDRESS}~typo"), &m));
        assert!(!is_payable(&format!("{ADDRESS}~split"), &[]), "no modifier is configured");
        assert!(
            is_payable(&format!("{ADDRESS}.rig~typo"), &m),
            "the suffix follows the worker name, which the pool cuts off"
        );
    }

    fn hash_with_selector(rnd: u16) -> [u8; 32] {
        let mut h = [0u8; 32];
        let b = rnd.to_le_bytes();
        h[31] = b[0];
        h[30] = b[1];
        h
    }

    fn modifiers() -> Vec<UsernameModifier> {
        vec![UsernameModifier {
            name: "split".to_string(),
            ranges: vec![
                ModifierRange { address: "bc1qfirst".to_string(), proportion: 0.3 },
                ModifierRange { address: String::new(), proportion: 0.5 },
            ],
        }]
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

    fn datum(full_users: bool, workers: bool) -> DatumConfig {
        DatumConfig {
            pool_pass_full_users: full_users,
            pool_pass_workers: workers,
            ..DatumConfig::default()
        }
    }

    #[test]
    fn the_wire_username_follows_pool_pass_full_users_and_pool_pass_workers() {
        let wire = |full_users, workers, username| {
            for_wire(&datum(full_users, workers), "bc1qpool", username)
        };
        assert_eq!(wire(true, true, "bc1qme.rig"), "bc1qme.rig");
        assert_eq!(wire(false, true, "rig"), "bc1qpool.rig");
        assert_eq!(wire(false, true, ".rig"), "bc1qpool.rig", "the username's own dot is kept");
        assert_eq!(wire(true, true, ".rig"), "bc1qpool.rig", "a leading dot names no address");
        assert_eq!(wire(false, false, "bc1qme.rig"), "bc1qpool");
        assert_eq!(wire(true, true, ""), "bc1qpool");
    }

    #[test]
    fn a_wire_username_over_the_limit_is_cut_on_a_character_boundary() {
        let mut long = "a".repeat(MAX_USERNAME_LEN - 1);
        long.push('\u{e9}');
        assert_eq!(long.len(), MAX_USERNAME_LEN + 1, "the last character takes two bytes");
        let cut = for_wire(&datum(true, true), "bc1qpool", &long);
        assert_eq!(cut.len(), MAX_USERNAME_LEN - 1, "the split character is dropped whole");
        assert_eq!(cut, "a".repeat(MAX_USERNAME_LEN - 1));
    }

    #[test]
    fn no_modifier_or_an_unknown_one_leaves_the_username_alone() {
        let m = modifiers();
        assert_eq!(apply_modifier(&m, "p", "bc1qme.rig", &[0; 32]), None);
        assert_eq!(apply_modifier(&m, "p", "bc1qme.rig~other", &[0; 32]), None);
    }
}
