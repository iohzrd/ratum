//! SipHash-2-4, which the short transaction ids of the validation exchange are taken from.

pub fn siphash24(key: &[u8; 16], data: &[u8]) -> u64 {
    let [k0, k1] = key.as_chunks::<8>().0 else { unreachable!("16 bytes hold two words") };
    let (k0, k1) = (u64::from_le_bytes(*k0), u64::from_le_bytes(*k1));
    let mut v0 = k0 ^ 0x736f_6d65_7073_6575;
    let mut v1 = k1 ^ 0x646f_7261_6e64_6f6d;
    let mut v2 = k0 ^ 0x6c79_6765_6e65_7261;
    let mut v3 = k1 ^ 0x7465_6462_7974_6573;

    let (chunks, tail) = data.as_chunks::<8>();
    for c in chunks {
        let m = u64::from_le_bytes(*c);
        v3 ^= m;
        double_round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
    }
    let mut b = (data.len() as u64) << 56;
    for (i, byte) in tail.iter().enumerate() {
        b |= u64::from(*byte) << (8 * i);
    }
    v3 ^= b;
    double_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= b;
    v2 ^= 0xff;
    double_round(&mut v0, &mut v1, &mut v2, &mut v3);
    double_round(&mut v0, &mut v1, &mut v2, &mut v3);
    (v0 ^ v1) ^ (v2 ^ v3)
}

fn half_round(a: &mut u64, b: &mut u64, c: &mut u64, d: &mut u64, e: u32, f: u32) {
    *a = a.wrapping_add(*b);
    *c = c.wrapping_add(*d);
    *b = b.rotate_left(e) ^ *a;
    *d = d.rotate_left(f) ^ *c;
    *a = a.rotate_left(32);
}

fn double_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    half_round(v0, v1, v2, v3, 13, 16);
    half_round(v2, v1, v0, v3, 17, 21);
    half_round(v0, v1, v2, v3, 13, 16);
    half_round(v2, v1, v0, v3, 17, 21);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::ramp;

    const KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    #[test]
    fn siphash_matches_the_gateway() {
        assert_eq!(siphash24(&KEY, &ramp(0x00)), 0x7127_512f_72f2_7cce);
        assert_eq!(siphash24(&KEY, &ramp(0x20)), 0xc46d_4c33_58ae_89a5);
        assert_eq!(siphash24(&KEY, &ramp(0x40)), 0x27bd_5ecb_84e5_6c87);
        assert_eq!(siphash24(&KEY, &ramp(0x60)), 0x1d82_9164_c5ef_ca0b);
        assert_eq!(siphash24(&KEY, &[0u8; 32]), 0x8990_d3e4_2994_96f4);
        assert_eq!(siphash24(&KEY, &[0xffu8; 32]), 0xe104_1d47_f898_e431);
        assert_eq!(siphash24(&[0u8; 16], &[0u8; 32]), 0x6c37_e103_dfa2_827d);
        let mut swapped = KEY;
        swapped.rotate_left(8);
        assert_ne!(siphash24(&swapped, &ramp(0)), 0x7127_512f_72f2_7cce);
    }
}
