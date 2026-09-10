pub type Target = [u8; 32];

const TARGET_BYTES: usize = 32;
pub const DIFF1_EXPONENT: u32 = 224;

const COMPACT_SIZE_SHIFT: u32 = 24;
const COMPACT_MANTISSA_MASK: u32 = 0x007f_ffff;
const COMPACT_SIGN_BIT: u32 = 0x0080_0000;
const COMPACT_MANTISSA_SIGN: u32 = 0x80;
const MAX_COMPACT_SIZE: usize = 34;

const QUOTIENT_BITS: i32 = 64;
const QUOTIENT_BYTES: usize = 12;

pub const MAX_TARGET_POT: u8 = (u64::BITS - 1) as u8;

pub const DIFF1_TARGET: Target = target_for_pot(0);

pub fn bits_to_target(bits: u32) -> Option<Target> {
    if bits & COMPACT_SIGN_BIT != 0 {
        return None;
    }
    let exp = (bits >> COMPACT_SIZE_SHIFT) as isize;
    if exp > MAX_COMPACT_SIZE as isize {
        return None;
    }
    let mut t = [0u8; TARGET_BYTES];
    for (i, b) in (bits & COMPACT_MANTISSA_MASK).to_be_bytes()[1..].iter().enumerate() {
        match TARGET_BYTES as isize - exp + i as isize {
            at if at >= TARGET_BYTES as isize => {}
            at if at >= 0 => t[at as usize] = *b,
            _ if *b == 0 => {}
            _ => return None,
        }
    }
    Some(t)
}

pub fn meets_target(hash: &[u8; 32], target: &Target) -> bool {
    hash <= target
}

pub const fn target_for_pot(exponent: u8) -> Target {
    let mut t = [0u8; TARGET_BYTES];
    let bit = DIFF1_EXPONENT.saturating_sub(exponent as u32);
    t[TARGET_BYTES - 1 - (bit / 8) as usize] = 1 << (bit % 8);
    t
}

pub fn target_for_difficulty(diff: f64) -> Target {
    if diff.is_nan() || diff <= 0.0 {
        return [0xff; TARGET_BYTES];
    }
    let q = 2f64.powi(QUOTIENT_BITS) / diff;
    if !q.is_finite() || q >= 2f64.powi(8 * QUOTIENT_BYTES as i32) {
        return [0xff; TARGET_BYTES];
    }
    let q = (q as u128).max(1);
    let qb = q.to_be_bytes();
    let mut t = [0u8; TARGET_BYTES];
    t[..QUOTIENT_BYTES].copy_from_slice(&qb[size_of::<u128>() - QUOTIENT_BYTES..]);
    t
}

pub fn difficulty_from_bits(bits: u32) -> Option<f64> {
    let target = bits_to_target(bits)?;
    let t = be_to_f64(&target);
    if t <= 0.0 {
        return None;
    }
    Some(be_to_f64(&DIFF1_TARGET) / t)
}

fn be_to_f64(v: &Target) -> f64 {
    v.iter().fold(0.0f64, |out, b| out.mul_add(256.0, f64::from(*b)))
}

fn share_target(exponent: u8) -> Target {
    const HIGH_ZERO_BYTES: usize = TARGET_BYTES - (DIFF1_EXPONENT as usize / 8);
    let mut t = [0u8; TARGET_BYTES];
    if u32::from(exponent) < DIFF1_EXPONENT {
        let first_set = HIGH_ZERO_BYTES + usize::from(exponent / 8);
        t[first_set..].fill(0xff);
        t[first_set] = 0xff >> (exponent % 8);
    }
    t
}

fn target_to_bits(target: &Target) -> u32 {
    let Some(first) = target.iter().position(|&b| b != 0) else { return 0 };
    let size = (TARGET_BYTES - first) as u32;
    let at = |i: usize| u32::from(target.get(i).copied().unwrap_or(0));
    let (m0, m1, m2) = (at(first), at(first + 1), at(first + 2));
    if m0 & COMPACT_MANTISSA_SIGN != 0 {
        ((size + 1) << COMPACT_SIZE_SHIFT) | (m0 << 8) | m1
    } else {
        (size << COMPACT_SIZE_SHIFT) | (m0 << 16) | (m1 << 8) | m2
    }
}

pub fn share_nbits(exponent: u8) -> u32 {
    target_to_bits(&share_target(exponent))
}

pub fn floor_pot(diff: u64) -> u8 {
    if diff == 0 { 0 } else { diff.ilog2() as u8 }
}

pub fn diff_for_pot(exponent: u8) -> u64 {
    1u64 << (u32::from(exponent) & (u64::BITS - 1))
}

pub fn pow2_floor(v: u64) -> u64 {
    if v == 0 { 0 } else { 1u64 << floor_pot(v) }
}

pub fn pow2_ceil(v: u64) -> u64 {
    if v == 0 { 0 } else { v.checked_next_power_of_two().unwrap_or(1u64 << (u64::BITS - 1)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_compact_values() {
        let t = bits_to_target(0x1d00ffff).unwrap();
        let mut bdiff_one = [0u8; 32];
        bdiff_one[4] = 0xff;
        bdiff_one[5] = 0xff;
        assert_eq!(t, bdiff_one);
        assert_ne!(t, DIFF1_TARGET);
        let t = bits_to_target(0x1b0404cb).unwrap();
        let mut e = [0u8; 32];
        e[5] = 0x04;
        e[6] = 0x04;
        e[7] = 0xcb;
        assert_eq!(t, e);
        let t = bits_to_target(0x03123456).unwrap();
        let mut e = [0u8; 32];
        e[29..].copy_from_slice(&[0x12, 0x34, 0x56]);
        assert_eq!(t, e);
        let t = bits_to_target(0x207fffff).unwrap();
        assert_eq!(&t[..3], &[0x7f, 0xff, 0xff]);
        assert!(t[3..].iter().all(|&b| b == 0));
    }

    #[test]
    fn mainnet_post_shift_bits_match_the_node_exactly() {
        let t = bits_to_target(0x1a008d4f).unwrap();
        let mut e = [0u8; 32];
        e[7] = 0x8d;
        e[8] = 0x4f;
        assert_eq!(hex::encode(t), hex::encode(e));
        let d = difficulty_from_bits(0x1a008d4f).unwrap();
        let pdiff = 2f64.powi(40) / f64::from(0x8d4f);
        assert!((d - pdiff).abs() < 1.0, "pdiff {d} want {pdiff}");
        assert!(meets_target(&e, &t));
        let mut over = e;
        over[9] = 0x01;
        assert!(!meets_target(&over, &t));
        let mut under = e;
        under[8] = 0x4e;
        under[9] = 0xff;
        assert!(meets_target(&under, &t));
    }

    #[test]
    fn accepts_the_high_exponents_setcompact_accepts() {
        let t = bits_to_target(0x2100ffff).expect("exponent 33, mantissa 0x00ffff");
        assert_eq!(t[0], 0xff);
        assert_eq!(t[1], 0xff);
        assert!(t[2..].iter().all(|&b| b == 0));

        let t = bits_to_target(0x220000ff).expect("exponent 34, mantissa 0x0000ff");
        assert_eq!(t[0], 0xff);
        assert!(t[1..].iter().all(|&b| b == 0));

        assert_eq!(bits_to_target(0x2101ffff), None);
        assert_eq!(bits_to_target(0x2200ffff), None);
        assert_eq!(bits_to_target(0x23000001), None);
        assert_eq!(bits_to_target(0x23000000), None, "exponent 35 is refused, mantissa 0 included");
    }

    #[test]
    fn difficulty_targets_are_exact_powers_of_two() {
        assert_eq!(target_for_difficulty(1.0), DIFF1_TARGET);
        for k in 0..64u32 {
            let t = target_for_difficulty(2f64.powi(k as i32));
            let bit = 224 - k;
            let byte = 31 - (bit / 8) as usize;
            let mut e = [0u8; 32];
            e[byte] = 1 << (bit % 8);
            assert_eq!(t, e, "difficulty 2^{k}");
        }
        let t3 = target_for_difficulty(3.0);
        assert!(t3 < target_for_difficulty(2.0));
        assert!(t3 > target_for_difficulty(4.0));
    }

    #[test]
    fn power_of_two_targets_match_the_gateway_exactly() {
        let vectors: &[(u8, &str)] = &[
            (0, "0000000100000000000000000000000000000000000000000000000000000000"),
            (1, "0000000080000000000000000000000000000000000000000000000000000000"),
            (2, "0000000040000000000000000000000000000000000000000000000000000000"),
            (8, "0000000001000000000000000000000000000000000000000000000000000000"),
            (10, "0000000000400000000000000000000000000000000000000000000000000000"),
            (14, "0000000000040000000000000000000000000000000000000000000000000000"),
            (16, "0000000000010000000000000000000000000000000000000000000000000000"),
            (20, "0000000000001000000000000000000000000000000000000000000000000000"),
            (32, "0000000000000001000000000000000000000000000000000000000000000000"),
            (40, "0000000000000000010000000000000000000000000000000000000000000000"),
        ];
        for (exponent, want) in vectors {
            assert_eq!(hex::encode(target_for_pot(*exponent)), *want, "2^{exponent}");
            assert_eq!(
                target_for_difficulty(2f64.powi(i32::from(*exponent))),
                target_for_pot(*exponent),
                "2^{exponent}"
            );
        }
        assert_eq!(target_for_pot(224)[31], 1);
        assert_eq!(target_for_pot(255)[31], 1);
    }

    #[test]
    fn difficulty_1_is_the_top_32_bits_being_zero() {
        let mut just_under = [0xffu8; 32];
        just_under[0] = 0;
        just_under[1] = 0;
        just_under[2] = 0;
        just_under[3] = 0;
        assert!(meets_target(&just_under, &DIFF1_TARGET));
        let mut just_over = [0u8; 32];
        just_over[3] = 0x02;
        assert!(!meets_target(&just_over, &DIFF1_TARGET));
    }

    #[test]
    fn difficulty_from_compact_bits() {
        let one = difficulty_from_bits(0x1d00ffff).unwrap();
        assert!((one - 65536.0 / 65535.0).abs() < 1e-12, "got {one}");
        let d = difficulty_from_bits(0x1c00ffff).unwrap();
        assert!((d / one - 256.0).abs() < 1e-9, "got {d}");
        let d = difficulty_from_bits(0x1702353d).unwrap();
        assert!(d > 1e14 && d < 1e15, "got {d}");
        let d = difficulty_from_bits(0x207fffff).unwrap();
        assert!(d > 0.0 && d < 1e-8, "got {d}");
        assert_eq!(difficulty_from_bits(0x1d80ffff), None);
    }

    #[test]
    fn share_nbits_matches_the_c_vectors() {
        assert_eq!(share_nbits(0), 0x1d00ffff);
        assert_eq!(share_nbits(1), 0x1c7fffff);
        assert_eq!(share_nbits(2), 0x1c3fffff);
        assert_eq!(share_nbits(8), 0x1c00ffff);
        assert_eq!(share_nbits(224), 0);
        assert_eq!(share_nbits(255), 0);
        for pot in 0..224u8 {
            let advertised = bits_to_target(share_nbits(pot)).expect("compact decodes");
            assert!(
                meets_target(&advertised, &target_for_pot(pot)),
                "pot {pot}: advertised target is easier than the share target"
            );
        }
    }

    #[test]
    fn pot() {
        assert_eq!(floor_pot(1), 0);
        assert_eq!(floor_pot(4096), 12);
        assert_eq!(floor_pot(4097), 12);
        assert_eq!(floor_pot(u64::MAX), 63);
        assert_eq!(diff_for_pot(14), 16384);
        assert_eq!(diff_for_pot(0), 1);
        assert_eq!(diff_for_pot(64), 1, "masked");
    }

    #[test]
    fn powers_of_two_round_both_ways() {
        assert_eq!(pow2_floor(0), 0);
        assert_eq!(pow2_floor(1), 1);
        assert_eq!(pow2_floor(4097), 4096);
        assert_eq!(pow2_floor(u64::MAX), 1 << 63);
        assert_eq!(pow2_ceil(0), 0);
        assert_eq!(pow2_ceil(1), 1);
        assert_eq!(pow2_ceil(4096), 4096);
        assert_eq!(pow2_ceil(4097), 8192);
        assert_eq!(pow2_ceil(u64::MAX), 1 << 63);
    }
}
