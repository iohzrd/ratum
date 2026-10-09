//! `stratum.vardiff_min` as the C gateway reads it (`datum_config_parse_difficulty`): an integer
//! up to `i32::MAX` is a share difficulty; a larger integer, a real, or a decimal string with an
//! optional SI suffix is a hash count, share difficulty * 2^32.

use ratum::target::pow2_ceil;
use serde_json::Value;
use std::cmp::Ordering;

/// The largest share difficulty: `i32::MAX` rounded down to a power of two, as in C.
pub const MAX: u64 = 1 << 30;
const HASHES_SHIFT: u32 = 32;
const SUFFIXES: &str = "KMGTPEZYRQ";

#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    /// A hash count equal to `difficulty << 32` within the input's last digit.
    Exact(u64),
    /// A hash count below `difficulty << 32`, the smallest power of two above it.
    RoundedUp(u64),
    /// An integer up to `i32::MAX`: a share difficulty, not checked for a power of two.
    Legacy(u64),
}

/// `None` for a value that is not positive, above `MAX << 32` hashes, or not a number or a
/// decimal string (digits, at most one `.`, one optional suffix, no sign or exponent).
pub fn parse(value: &Value) -> Option<Parsed> {
    match value {
        Value::Number(n) => match n.as_u64() {
            Some(n) => Some(parse_integer(n)?),
            None if n.is_i64() => None,
            None => parse_real(n.as_f64()?),
        },
        Value::String(s) => parse_decimal(s),
        _ => None,
    }
}

fn parse_integer(n: u64) -> Option<Parsed> {
    if n == 0 {
        return None;
    }
    if n <= i32::MAX as u64 {
        return Some(Parsed::Legacy(n));
    }
    let minimum = n.div_ceil(1 << HASHES_SHIFT);
    if minimum > MAX {
        return None;
    }
    let d = pow2_ceil(minimum);
    Some(if d << HASHES_SHIFT > n { Parsed::RoundedUp(d) } else { Parsed::Exact(d) })
}

fn parse_real(hashes: f64) -> Option<Parsed> {
    if !hashes.is_finite() || hashes <= 0.0 || hashes > (MAX << HASHES_SHIFT) as f64 {
        return None;
    }
    let d = estimate(hashes);
    Some(if (d << HASHES_SHIFT) as f64 > hashes { Parsed::RoundedUp(d) } else { Parsed::Exact(d) })
}

/// The smallest power of two whose hash count is at least `hashes`, at most `MAX`.
fn estimate(hashes: f64) -> u64 {
    let minimum = (hashes / (1u64 << HASHES_SHIFT) as f64).min(MAX as f64).ceil() as u64;
    pow2_ceil(minimum.max(1))
}

/// A decimal string as `digits * 10^exponent`, `digits` without leading zeros.
struct Decimal {
    digits: String,
    exponent: i64,
}

impl Decimal {
    /// `self` against `boundary` hashes rounded half up to the units of the last digit given,
    /// so "4.4T" equals 4398046511104.
    fn cmp_boundary(&self, boundary: u64) -> Ordering {
        let boundary = if self.exponent > 0 {
            let unit = u32::try_from(self.exponent - 1).ok().and_then(|e| 10u128.checked_pow(e));
            let rounded = unit.map_or(0, |u| (u128::from(boundary) + 5 * u) / (10 * u));
            if rounded == 0 {
                return Ordering::Greater;
            }
            rounded.to_string()
        } else {
            boundary.to_string() + &"0".repeat(self.exponent.unsigned_abs() as usize)
        };
        self.digits.len().cmp(&boundary.len()).then_with(|| self.digits.as_str().cmp(&boundary))
    }
}

fn parse_decimal(s: &str) -> Option<Parsed> {
    let (number, suffix_exponent) = match s.char_indices().last()? {
        (i, c) if c.is_ascii_alphabetic() => {
            let k = SUFFIXES.find(c.to_ascii_uppercase())?;
            (&s[..i], 3 * (k as i64 + 1))
        }
        _ => (s, 0),
    };
    let (int, frac) = number.split_once('.').unwrap_or((number, ""));
    if int.len() + frac.len() == 0 || !int.bytes().chain(frac.bytes()).all(|b| b.is_ascii_digit()) {
        return None;
    }
    let hashes = number.parse::<f64>().ok()? * 10f64.powi(suffix_exponent as i32);
    let digits = format!("{int}{frac}").trim_start_matches('0').to_string();
    if digits.is_empty() || !hashes.is_finite() {
        return None;
    }
    let dec = Decimal { digits, exponent: suffix_exponent - frac.len() as i64 };

    let mut d = estimate(hashes);
    if d > 1 && dec.cmp_boundary((d / 2) << HASHES_SHIFT) != Ordering::Greater {
        d /= 2;
    } else if dec.cmp_boundary(d << HASHES_SHIFT) == Ordering::Greater {
        if d >= MAX {
            return None;
        }
        d *= 2;
    }
    Some(if dec.cmp_boundary(d << HASHES_SHIFT) == Ordering::Less {
        Parsed::RoundedUp(d)
    } else {
        Parsed::Exact(d)
    })
}

/// A hash count as C's `datum_format_difficulty` prints it: "4.4T", or an integer below 1000.
pub fn format(difficulty: u64) -> String {
    let mut v = (u128::from(difficulty) << HASHES_SHIFT) as f64;
    if v < 1000.0 {
        return format!("{v:.0}");
    }
    let suffixes = b"kMGTPEZYRQ";
    let mut i = 0;
    v /= 1000.0;
    while v >= 999.95 && i + 1 < suffixes.len() {
        v /= 1000.0;
        i += 1;
    }
    format!("{v:.1}{}", suffixes[i] as char)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// C's `datum_conf_difficulty_tests`: `None` where C returns -1, `RoundedUp` where 2.
    #[test]
    fn parses_as_c_does() {
        use Parsed::*;
        let cases: &[(Value, Option<Parsed>)] = &[
            (json!(1023), Some(Legacy(1023))),
            (json!("1023"), Some(RoundedUp(1))),
            (json!(1024), Some(Legacy(1024))),
            (json!("1024"), Some(RoundedUp(1))),
            (json!(4398046511104u64), Some(Exact(1024))),
            (json!("4398046511104"), Some(Exact(1024))),
            (json!(4400000000000u64), Some(RoundedUp(2048))),
            (json!(18014398509481984u64), Some(Exact(1 << 22))),
            (json!(18014398509481985u64), Some(RoundedUp(1 << 23))),
            (json!("18014398509481983"), Some(RoundedUp(1 << 22))),
            (json!("18014398509481984"), Some(Exact(1 << 22))),
            (json!("18014398509481985"), Some(RoundedUp(1 << 23))),
            (json!("00018014398509481984.000"), Some(Exact(1 << 22))),
            (json!("18014398509481983.999"), Some(RoundedUp(1 << 22))),
            (json!("18014398509481984.001"), Some(RoundedUp(1 << 23))),
            (
                json!("18014398509481984.0000000000000000000000000000000000000000000000000"),
                Some(Exact(1 << 22)),
            ),
            (
                json!("18014398509481985.0000000000000000000000000000000000000000000000000"),
                Some(RoundedUp(1 << 23)),
            ),
            (json!("18.014398509481984P"), Some(Exact(1 << 22))),
            (json!("18.014398509481985P"), Some(RoundedUp(1 << 23))),
            (json!("18.014398509481983P"), Some(RoundedUp(1 << 22))),
            (json!("18014398509481.98k"), Some(Exact(1 << 22))),
            (json!("18014398509481.99k"), Some(RoundedUp(1 << 23))),
            (json!("4611686018427387904"), Some(Exact(1 << 30))),
            (json!("4611686018427387903"), Some(RoundedUp(1 << 30))),
            (json!("4611686018427387905"), None),
            (json!("4.611686018427387904E"), Some(Exact(1 << 30))),
            (json!("4.611686018427387905E"), None),
            (json!(4398046511104.0), Some(Exact(1024))),
            (json!(18014398509481984.0), Some(Exact(1 << 22))),
            (json!(18014398509481988.0), Some(RoundedUp(1 << 23))),
            (json!(0.0), None),
            (json!(-1.0), None),
            (json!(1e20), None),
            (json!("4G"), Some(Exact(1))),
            (json!("4.4T"), Some(Exact(1024))),
            (json!("4.40T"), Some(Exact(1024))),
            (json!("4.400T"), Some(RoundedUp(2048))),
            (json!("4.5T"), Some(RoundedUp(2048))),
            (json!("2T"), Some(Exact(512))),
            (json!("1T"), Some(Exact(128))),
            (json!("1E"), Some(Exact(1 << 27))),
            (json!("0.0000000000000000044Q"), Some(Exact(1024))),
            (json!("4.6E"), Some(Exact(1 << 30))),
            (json!("1.2Z"), None),
            (json!("1Q"), None),
            (json!("4.4X"), None),
            (json!("4.4\u{e9}"), None),
            (json!("4e12"), None),
            (json!("4.4e12"), None),
            (json!("0x1p42"), None),
            // Beyond C's cases.
            (json!(0), None),
            (json!(-1), None),
            (json!("0"), None),
            (json!("."), None),
            (json!(""), None),
            (json!("T"), None),
            (json!(" 4T"), None),
            (json!("+4T"), None),
            (json!("4..4T"), None),
            (json!(true), None),
        ];
        for (input, expected) in cases {
            assert_eq!(&parse(input), expected, "{input}");
        }
    }

    #[test]
    fn formats_as_c_does() {
        assert_eq!(format(1024), "4.4T");
        assert_eq!(format(512), "2.2T");
        assert_eq!(format(16384), "70.4T");
        assert_eq!(format(1), "4.3G");
        assert_eq!(format(1 << 63), "39.6R");
    }

    #[test]
    fn formatted_values_parse_to_the_same_difficulty() {
        for shift in 0..=30 {
            let d = 1u64 << shift;
            assert_eq!(parse(&json!(format(d))), Some(Parsed::Exact(d)), "{}", format(d));
        }
    }
}
