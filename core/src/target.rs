pub type Target = [u8; 32];

const TARGET_BYTES: usize = 32;
pub const DIFF1_EXPONENT: u32 = 224;

const COMPACT_SIZE_SHIFT: u32 = 24;
const COMPACT_MANTISSA_MASK: u32 = 0x007f_ffff;
const COMPACT_SIGN_BIT: u32 = 0x0080_0000;
const COMPACT_MANTISSA_SIGN: u32 = 0x80;
const COMPACT_MANTISSA_BYTES: usize = 3;
const MAX_COMPACT_SIZE: usize = 34;

/// `target_for_difficulty` divides 2^QUOTIENT_BITS by the difficulty and writes the
/// quotient into the top QUOTIENT_BYTES of the target.
const QUOTIENT_BITS: i32 = 64;
const QUOTIENT_BYTES: usize = 12;

pub const MAX_TARGET_POT: u8 = (u64::BITS - 1) as u8;

pub const DIFF1_TARGET: Target = target_for_pot(0);

/// The 256-bit target an nBits compact encoding stands for: a 3-byte mantissa scaled by
/// 256^(size - 3). None for a negative encoding, and for one whose mantissa would carry a
/// set bit past the top of the target.
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

/// The largest target a share at difficulty `2^exponent` may have: difficulty-1's target
/// with every bit below its leading bit set, shifted down by `exponent`. An exponent at or
/// above `DIFF1_EXPONENT` leaves no bit to set and gives a zero target.
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

/// The inverse of `bits_to_target`. A zero target encodes as 0.
fn target_to_bits(target: &Target) -> u32 {
    let Some(first) = target.iter().position(|&b| b != 0) else { return 0 };
    let size = (TARGET_BYTES - first) as u32;
    let at = |i: usize| u32::from(target.get(i).copied().unwrap_or(0));
    let (m0, m1, m2) = (at(first), at(first + 1), at(first + 2));
    // A mantissa whose top byte has its high bit set would read as negative, so it is
    // shifted down a byte and the size raised to compensate.
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
