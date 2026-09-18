//! Random bytes from the libsodium generator.

pub fn fill(buf: &mut [u8]) {
    dryoc::rng::copy_randombytes(buf);
}

pub fn bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    fill(&mut b);
    b
}

pub fn u32() -> u32 {
    u32::from_le_bytes(bytes())
}
