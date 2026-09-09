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
