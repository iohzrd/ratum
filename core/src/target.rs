pub type Target = [u8; 32];

/// The bytes a target occupies, `uint256`.
const TARGET_BYTES: usize = 32;
/// The bits of a target above pdiff 1, which is `1 << DIFF1_EXPONENT`. A power-of-two share
/// target names its difficulty by the exponent it subtracts from this.
pub const DIFF1_EXPONENT: u32 = 224;

/// The compact target encoding (`arith_uint256::SetCompact`): the high byte is the size, the
/// low three the mantissa, whose top bit is the sign.
const COMPACT_SIZE_SHIFT: u32 = 24;
const COMPACT_MANTISSA_MASK: u32 = 0x007f_ffff;
const COMPACT_SIGN_BIT: u32 = 0x0080_0000;
const COMPACT_MANTISSA_BYTES: usize = 3;
/// The largest size `SetCompact` decodes without reporting overflow (`nSize > 34`); a
/// mantissa with more significant bytes overflows at a smaller size, which the loop below
/// reports by finding a nonzero byte past the end of the target.
const MAX_COMPACT_SIZE: usize = 34;

/// pdiff 1: exactly 2^224. Not bdiff 1, the target compact bits 0x1d00ffff encode, which
/// is 65535/65536 of this. Share targets here are pdiff throughout.
pub const DIFF1_TARGET: Target = target_for_pot(0);

pub fn bits_to_target(bits: u32) -> Option<Target> {
    let exp = (bits >> COMPACT_SIZE_SHIFT) as usize;
    let mant = bits & COMPACT_MANTISSA_MASK;
    if bits & COMPACT_SIGN_BIT != 0 {
        return None;
    }
    if exp > MAX_COMPACT_SIZE {
        return None;
    }
    let mut t = [0u8; TARGET_BYTES];
    let m = mant.to_be_bytes();
    if exp <= COMPACT_MANTISSA_BYTES {
        // The mantissa is shifted down into the low bytes rather than up into the target.
        let v = mant >> (8 * (COMPACT_MANTISSA_BYTES - exp));
        t[TARGET_BYTES - COMPACT_MANTISSA_BYTES..].copy_from_slice(&v.to_be_bytes()[1..]);
        return Some(t);
    }
    let end = TARGET_BYTES.checked_sub(exp - COMPACT_MANTISSA_BYTES)?;
    for (i, b) in m[1..].iter().enumerate() {
        match end.checked_sub(COMPACT_MANTISSA_BYTES - i) {
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

/// The target of difficulty `2^exponent`: the single bit `DIFF1_EXPONENT - exponent`, or the
/// lowest bit for an exponent at or above `DIFF1_EXPONENT`, where the bit would run off the
/// bottom of the 256-bit value.
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
    // The quotient occupies the top 12 bytes, making the target (2^64 / diff) << 160. A
    // difficulty above 2^64 would make the quotient less than one and the target all zeros,
    // which no hash can meet, so a miner would search forever; clamp it to the hardest target
    // this representation holds instead.
    let q = (q as u128).max(1);
    let qb = q.to_be_bytes();
    let mut t = [0u8; TARGET_BYTES];
    t[..QUOTIENT_BYTES].copy_from_slice(&qb[size_of::<u128>() - QUOTIENT_BYTES..]);
    t
}

/// `target_for_difficulty` computes `2^64 / diff` and shifts it left by 160 bits, which puts
/// the quotient in the target's top twelve bytes and makes difficulty 1 exactly 2^224.
const QUOTIENT_BITS: i32 = 64;
const QUOTIENT_BYTES: usize = 12;

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
    v.iter().fold(0.0f64, |out, b| out * 256.0 + f64::from(*b))
}

/// The compact bits a version 3 gateway advertises to hashers in place of the
/// consensus nBits (`datum_blake2b_share_nbits`): the compact encoding of the C share
/// target `(2^224 - 1) >> exponent`, whose mantissa truncation makes the advertised value
/// never easier than the share target. Returns 0 for an exponent of 224 or more, which the
/// C function treats as failure.
pub fn share_nbits(exponent: u8) -> u32 {
    if u32::from(exponent) >= DIFF1_EXPONENT {
        return 0;
    }
    // (2^224 - 1) >> exponent, big-endian: `datum_blake2b_share_target` fills the low 28
    // bytes with 0xff and shifts the whole value down by the exponent.
    const HIGH_ZERO_BYTES: usize = TARGET_BYTES - (DIFF1_EXPONENT as usize / 8);
    let mut t = [0u8; TARGET_BYTES];
    let first_set = HIGH_ZERO_BYTES + usize::from(exponent / 8);
    t[first_set..].fill(0xff);
    t[first_set] = 0xff >> (exponent % 8);
    // The compact encoding of `t`, as `datum_blake2b_share_nbits` writes it: a mantissa whose
    // top bit is set would read as negative, so the size goes up one and the mantissa down a
    // byte, truncating it and making the encoded target never easier than `t`.
    let first = t.iter().position(|&b| b != 0).expect("nonzero below DIFF1_EXPONENT");
    let size = (TARGET_BYTES - first) as u32;
    let at = |i: usize| u32::from(t.get(i).copied().unwrap_or(0));
    let (m0, m1, m2) = (at(first), at(first + 1), at(first + 2));
    if m0 & 0x80 != 0 {
        ((size + 1) << COMPACT_SIZE_SHIFT) | (m0 << 8) | m1
    } else {
        (size << COMPACT_SIZE_SHIFT) | (m0 << 16) | (m1 << 8) | m2
    }
}

/// `floor(log2(diff))`: the PoT (power-of-two) exponent of a difficulty.
pub fn floor_pot(diff: u64) -> u8 {
    if diff == 0 { 0 } else { (u64::BITS - 1 - diff.leading_zeros()) as u8 }
}

/// The largest PoT exponent a share target can name: `diff_for_pot` computes `2^exponent` in
/// a `u64`, so a larger exponent has no representable difficulty and the pool refuses the
/// share (`RejectReason::BadTarget`).
pub const MAX_TARGET_POT: u8 = (u64::BITS - 1) as u8;

/// The difficulty a PoT exponent names, `2^exponent`. Masked to the shift width because it is
/// also called on target bytes that have not been checked yet.
pub fn diff_for_pot(exponent: u8) -> u64 {
    1u64 << (u32::from(exponent) & (u64::BITS - 1))
}

/// The largest power of two at most `v`; 0 for 0.
pub fn pow2_floor(v: u64) -> u64 {
    if v == 0 { 0 } else { 1u64 << floor_pot(v) }
}

/// The smallest power of two at least `v`; 0 for 0, and 2^63 for a value above it.
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
        // Knots rc4 mainnet after the BLAKE2b shift: getblocktemplate reports bits 1a008d4f
        // and target 000000000000008d4f0000...00 (verified against a live node 2026-08-31).
        let t = bits_to_target(0x1a008d4f).unwrap();
        let mut e = [0u8; 32];
        e[7] = 0x8d;
        e[8] = 0x4f;
        assert_eq!(hex::encode(t), hex::encode(e));
        let d = difficulty_from_bits(0x1a008d4f).unwrap();
        let pdiff = 2f64.powi(40) / f64::from(0x8d4f);
        assert!((d - pdiff).abs() < 1.0, "pdiff {d} want {pdiff}");
        // The comparator at the boundary: equal meets, one past does not.
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
        // Values from datum_pow_tests.c on lukejr/tmp.
        assert_eq!(share_nbits(0), 0x1d00ffff);
        assert_eq!(share_nbits(1), 0x1c7fffff);
        assert_eq!(share_nbits(2), 0x1c3fffff);
        assert_eq!(share_nbits(8), 0x1c00ffff);
        assert_eq!(share_nbits(224), 0);
        assert_eq!(share_nbits(255), 0);
        // The C loop 0..224: the advertised target is never easier than the accepted one.
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
