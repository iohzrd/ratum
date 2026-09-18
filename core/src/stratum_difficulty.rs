//! The number a mining.set_difficulty carries. The gateway assigns an integer difficulty relative to
//! the 2^224 target (a pool difficulty, as the share's target byte counts it), and the C gateway
//! announces it as `n * 65535 / 65536`, the same target relative to the 0x1d00ffff difficulty-1
//! target most stratum firmware divides by. `format` is that announcement byte for byte, and
//! `pool_difficulty` the miner's way back to `n`.

/// The difficulty-1 target of stratum firmware over the gateway's: 0xffff * 2^208 over 2^224.
const DIFF1_RATIO_NUMERATOR: u128 = 0xffff;
const DIFF1_RATIO_SHIFT: u32 = 16;

/// The significand bits of the x87 extended `long double` the C gateway computes in.
const LONG_DOUBLE_SIGNIFICAND_BITS: u32 = 64;

/// 10^16 / 2^16: a fraction of 2^16 written in 16 decimal digits is its numerator times this.
const FRACTION_DECIMAL_SCALE: u128 = 152_587_890_625;
const FRACTION_DECIMAL_DIGITS: usize = 16;

/// The C gateway's `datum_blake2b_format_stratum_difficulty`: `n * 65535.0L / 65536.0L` printed
/// with `%.20Lf`, then trailing zeros and a trailing decimal point removed.
///
/// The product is rounded to the 64-bit significand of the x87 `long double` (round half to
/// even), as the C multiplication is; the division by 2^16 is exact in any binary format, and
/// a multiple of 2^-16 has at most 16 decimal places, so `%.20Lf` prints it without rounding.
/// Every product under 2^64 is exact, which covers every difficulty up to 2^48 and every
/// power of two.
pub fn format(n: u64) -> String {
    let product = round_to_significand(u128::from(n) * DIFF1_RATIO_NUMERATOR);
    let whole = product >> DIFF1_RATIO_SHIFT;
    let fraction = product & ((1 << DIFF1_RATIO_SHIFT) - 1);
    if fraction == 0 {
        return whole.to_string();
    }
    let digits =
        format!("{:0width$}", fraction * FRACTION_DECIMAL_SCALE, width = FRACTION_DECIMAL_DIGITS);
    format!("{whole}.{}", digits.trim_end_matches('0'))
}

/// `v` rounded to `LONG_DOUBLE_SIGNIFICAND_BITS` significant bits, half to even.
fn round_to_significand(v: u128) -> u128 {
    let bits = u128::BITS - v.leading_zeros();
    if bits <= LONG_DOUBLE_SIGNIFICAND_BITS {
        return v;
    }
    let shift = bits - LONG_DOUBLE_SIGNIFICAND_BITS;
    let kept = v >> shift;
    let dropped = v & ((1 << shift) - 1);
    let half = 1 << (shift - 1);
    let rounded =
        if dropped > half || (dropped == half && kept & 1 == 1) { kept + 1 } else { kept };
    rounded << shift
}

/// The integer difficulty a mining.set_difficulty announced as `announced`: the inverse of
/// `format`, rounded to the nearest integer. None for a value that is not positive and finite.
pub fn pool_difficulty(announced: f64) -> Option<f64> {
    if !announced.is_finite() || announced <= 0.0 {
        return None;
    }
    let ratio = DIFF1_RATIO_NUMERATOR as f64 / f64::from(1u32 << DIFF1_RATIO_SHIFT);
    Some((announced / ratio).round().max(1.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Printed by the C function itself, built with gcc on x86-64 (80-bit `long double`).
    const C_GATEWAY: [(u64, &str); 18] = [
        (0, "0"),
        (1, "0.9999847412109375"),
        (2, "1.999969482421875"),
        (3, "2.9999542236328125"),
        (1024, "1023.984375"),
        (16384, "16383.75"),
        (65535, "65534.0000152587890625"),
        (65536, "65535"),
        (65537, "65535.9999847412109375"),
        (524_288, "524280"),
        (1 << 40, "1099494850560"),
        (1 << 48, "281470681743360"),
        ((1 << 48) + 1, "281470681743360.9999847412109375"),
        (9_007_199_254_740_993, "9007061815787521"),
        (12_345_678_901_234_567, "12345490521124379.705078125"),
        (1 << 62, "4611615649683210240"),
        (1 << 63, "9223231299366420480"),
        (u64::MAX, "18446462598732840959"),
    ];

    #[test]
    fn the_announced_difficulty_is_the_c_gateways_byte_for_byte() {
        for (n, c) in C_GATEWAY {
            assert_eq!(format(n), c, "difficulty {n}");
        }
    }

    #[test]
    fn every_power_of_two_reads_back_as_itself() {
        for k in 0..u64::BITS {
            let n = 1u64 << k;
            let announced: f64 = format(n).parse().expect("a decimal");
            assert_eq!(pool_difficulty(announced), Some(n as f64), "2^{k}");
        }
        assert_eq!(pool_difficulty(0.0), None);
        assert_eq!(pool_difficulty(f64::NAN), None);
        assert_eq!(pool_difficulty(-1.0), None);
    }
}
