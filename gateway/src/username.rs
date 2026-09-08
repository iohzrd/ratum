use crate::address;

pub type Modifiers = Vec<(String, Vec<(String, f64)>)>;

/// The address a stratum username begins with: everything before the worker suffix
/// ('.') and before the modifier name ('~').
pub fn address_of(username: &str) -> &str {
    let end = username.find(['.', '~']).unwrap_or(username.len());
    &username[..end]
}

pub fn is_payable(username: &str) -> bool {
    let a = address_of(username);
    !a.is_empty() && a.len() < address::MAX_ADDRESS_CHARS && address::is_valid(a)
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
    let rnd = u32::from(u16::from_le_bytes([hash[31], hash[30]]));
    let worker = base.find('.').map_or("", |d| &base[d..]);
    let mut sum = 0f64;
    for (addr, proportion) in ranges {
        sum += proportion.max(0.0);
        let max = ((sum * SELECTOR_SPACE).ceil() as i64 - 1).min(SELECTOR_MAX);
        if max < 0 {
            continue;
        }
        if i64::from(rnd) <= max {
            return Some(if addr.is_empty() {
                base.to_string()
            } else {
                format!("{addr}{worker}")
            });
        }
        if max >= SELECTOR_MAX {
            break;
        }
    }
    Some(pool_address.to_string())
}
