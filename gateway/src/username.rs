//! What selects the username a share is credited to: the `~modifier` address ranges of
//! `stratum.username_modifiers` (`datum_stratum_mod_username`), and the gateway fee meter
//! that credits a portion of the work to the fee address (`stratum_fee_username`).

/// `stratum.username_modifiers` in the file's order: `(modifier name, [(address,
/// proportion)])`. The order selects which address takes the low hash values, as the C
/// gateway's `json_object_foreach` walk does.
pub type Modifiers = Vec<(String, Vec<(String, f64)>)>;

/// `~modname` username modifiers: the two low-order bytes of the share hash select an
/// address range. `hash` is the BLAKE2b output in display order, whose last two bytes are
/// the C gateway's `upk_u16le(share_hash, 0)` (its `share_hash` is the byte reversal); the
/// leading bytes are the proof of work's zeros and would select the first range every time.
/// A share past the last range goes to `pool_address`. `None` when the username carries no
/// modifier or names one that is not configured.
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
    let worker = base.find('.').map(|d| &base[d..]).unwrap_or("");
    let mut sum = 0f64;
    for (addr, proportion) in ranges.iter() {
        sum += proportion.max(0.0);
        let max = ((sum * 65536.0).ceil() as i64 - 1).min(0xffff);
        if max < 0 {
            continue;
        }
        if rnd as i64 <= max {
            return Some(if addr.is_empty() {
                base.to_string()
            } else {
                format!("{addr}{worker}")
            });
        }
        if max >= 0xffff {
            break;
        }
    }
    Some(pool_address.to_string())
}

/// The gateway fee, per connection: work owed to the fee address accumulates at
/// `gateway_fee_bps` of every share, and whenever the work of one share is owed that share
/// is credited to the fee address instead of the miner. The first share's owed work starts
/// at a random point within one share so the fee share does not land at a fixed position.
#[derive(Default)]
pub struct FeeMeter {
    owed: u64,
    started: bool,
}

impl FeeMeter {
    /// Account for a share of `diff` at `bps`; `true` when this share is the fee's. `seed`
    /// supplies the random start, called once.
    pub fn charge(&mut self, diff: u64, bps: u64, seed: impl FnOnce() -> u64) -> bool {
        if bps == 0 {
            return false;
        }
        let share_work = diff.saturating_mul(10_000);
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

#[cfg(test)]
mod tests {
    use super::*;

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
        // The first range listed takes the low values: 0..=0x4ccc goes to bc1qfirst
        // (ceil(0.3 * 65536) - 1), 0x4ccd..=0xcccc keeps the miner's own name, and the rest
        // goes to the pool address.
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

    #[test]
    fn the_fee_takes_its_share_of_the_work_to_within_one_share() {
        for bps in [1u64, 500, 2000, 5000, 9999] {
            let mut meter = FeeMeter::default();
            let mut charged = 0u64;
            let shares = 10_000u64;
            for _ in 0..shares {
                if meter.charge(4096, bps, || 12345) {
                    charged += 1;
                }
            }
            let expected = shares * bps / 10_000;
            assert!(
                charged.abs_diff(expected) <= 1,
                "{bps} bps: charged {charged}, expected {expected}"
            );
        }
    }

    #[test]
    fn no_fee_and_the_whole_fee() {
        let mut none = FeeMeter::default();
        assert!(!none.charge(4096, 0, || 0));
        let mut all = FeeMeter::default();
        for _ in 0..10 {
            assert!(all.charge(4096, 10_000, || 7));
        }
    }
}
