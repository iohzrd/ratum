pub type Modifiers = Vec<(String, Vec<(String, f64)>)>;

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
    for (addr, proportion) in ranges.iter() {
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

#[derive(Default)]
pub struct FeeMeter {
    owed: u64,
    started: bool,
}

impl FeeMeter {
    pub fn charge(&mut self, diff: u64, bps: u64, seed: impl FnOnce() -> u64) -> bool {
        if bps == 0 {
            return false;
        }
        let share_work = diff.saturating_mul(ratum::BASIS_POINTS_PER_UNIT);
        if !self.started {
            self.started = true;
            self.owed = seed() % share_work.max(1);
        }
        self.owed = self.owed.saturating_add(diff.saturating_mul(bps));
        if self.owed >= share_work {
            self.owed -= share_work;
            return true;
        }
        false
    }
}
