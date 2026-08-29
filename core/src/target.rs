pub type Target = [u8; 32];

/// pdiff 1: exactly 2^224. Not bdiff 1, the target compact bits 0x1d00ffff encode, which
/// is 65535/65536 of this. Share targets here are pdiff throughout.
pub const DIFF1_TARGET: Target = {
    let mut t = [0u8; 32];
    t[3] = 0x01;
    t
};

pub fn bits_to_target(bits: u32) -> Option<Target> {
    let exp = (bits >> 24) as usize;
    let mant = bits & 0x007f_ffff;
    if bits & 0x0080_0000 != 0 {
        return None;
    }
    if exp > 34 {
        return None;
    }
    let mut t = [0u8; 32];
    let m = mant.to_be_bytes();
    if exp <= 3 {
        let shift = 8 * (3 - exp);
        let v = mant >> shift;
        t[29..32].copy_from_slice(&v.to_be_bytes()[1..]);
        return Some(t);
    }
    let end = 32usize.checked_sub(exp - 3)?;
    for (i, b) in m[1..].iter().enumerate() {
        match end.checked_sub(3 - i) {
            Some(idx) => t[idx] = *b,
            None if *b == 0 => {}
            None => return None,
        }
    }
    Some(t)
}

pub fn meets_target(hash: &[u8; 32], target: &Target) -> bool {
    // Both are big-endian, so comparing the arrays compares the numbers.
    hash <= target
}

pub fn target_for_pot(exponent: u8) -> Target {
    let mut t = [0u8; 32];
    if exponent >= 224 {
        t[31] = 1;
        return t;
    }
    let bit = 224 - u32::from(exponent);
    t[31 - (bit / 8) as usize] = 1 << (bit % 8);
    t
}

pub fn target_for_difficulty(diff: f64) -> Target {
    if diff.is_nan() || diff <= 0.0 {
        return [0xff; 32];
    }
    let q = 2f64.powi(64) / diff;
    if !q.is_finite() || q >= 2f64.powi(96) {
        return [0xff; 32];
    }
    // The quotient occupies the top 12 bytes, making the target (2^64 / diff) << 160. A
    // difficulty above 2^64 would make the quotient less than one and the target all zeros,
    // which no hash can meet, so a miner would search forever; clamp it to the hardest target
    // this representation holds instead.
    let q = (q as u128).max(1);
    let qb = q.to_be_bytes();
    let mut t = [0u8; 32];
    t[..12].copy_from_slice(&qb[4..]);
    t
}

/// The pdiff difficulty of a compact target (2^224 / target), 65536/65535 of the bdiff value
/// the node reports as `difficulty`.
pub fn difficulty_from_bits(bits: u32) -> Option<f64> {
    let target = bits_to_target(bits)?;
    let t = be_to_f64(&target);
    if t <= 0.0 {
        return None;
    }
    Some(be_to_f64(&DIFF1_TARGET) / t)
}

fn be_to_f64(v: &Target) -> f64 {
    let mut out = 0.0f64;
    for b in v {
        out = out * 256.0 + f64::from(*b);
    }
    out
}

/// `floor(log2(diff))`: the PoT (power-of-two) exponent of a difficulty.
pub fn floor_pot(diff: u64) -> u8 {
    if diff == 0 { 0 } else { (63 - diff.leading_zeros()) as u8 }
}

/// The difficulty a PoT exponent names, `2^exponent`. Masked to 63 because it is also called
/// on target bytes that have not been checked yet.
pub fn diff_for_pot(exponent: u8) -> u64 {
    1u64 << (exponent & 63)
}

/// The largest power of two at most `v`; 0 for 0.
pub fn pow2_floor(v: u64) -> u64 {
    if v == 0 { 0 } else { 1u64 << (63 - v.leading_zeros()) }
}

/// The smallest power of two at least `v`; 0 for 0, and 2^63 for a value above it.
pub fn pow2_ceil(v: u64) -> u64 {
    if v == 0 { 0 } else { v.checked_next_power_of_two().unwrap_or(1u64 << 63) }
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
