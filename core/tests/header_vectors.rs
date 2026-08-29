use ratum::header::*;
use serde::Deserialize;

#[derive(Deserialize)]
struct Fields {
    #[serde(rename = "nVersion")]
    version: i32,
    #[serde(rename = "hashPrevBlock")]
    prev_block: String,
    #[serde(rename = "hashMerkleRoot")]
    merkle_root: String,
    #[serde(rename = "nTime")]
    time: u32,
    #[serde(rename = "nBits")]
    bits: u32,
    #[serde(rename = "nNonce")]
    nonce: u32,
    m_nonce2: u32,
    m_nonce3: u32,
    m_extranonce: String,
    m_time_offset: u32,
    m_txcount: u16,
    m_flags: u8,
    m_xor_key_mask_clear_bits: u8,
    m_xor_key: String,
    m_height: i32,
    m_mm_rhs: String,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    fields: Fields,
    serialized: String,
    xor_key_hash: String,
    h1: String,
    h2: String,
    blake2b_1: String,
    blake2b_2: String,
    mask: String,
    block_hash: String,
    asic_profile: u8,
    asic_input: String,
}

#[derive(Deserialize)]
struct File {
    headers: Vec<Vector>,
}

fn header_from(f: &Fields) -> HeaderV2 {
    HeaderV2 {
        version: f.version,
        prev_block: u256_from_display_hex(&f.prev_block).unwrap(),
        merkle_root: u256_from_display_hex(&f.merkle_root).unwrap(),
        time: f.time,
        bits: f.bits,
        nonce: f.nonce,
        nonce2: f.m_nonce2,
        nonce3: f.m_nonce3,
        extranonce: u128_from_display_hex(&f.m_extranonce).unwrap(),
        time_offset: f.m_time_offset,
        txcount: f.m_txcount,
        flags: f.m_flags,
        xor_key_mask_clear_bits: f.m_xor_key_mask_clear_bits,
        xor_key: u128_from_display_hex(&f.m_xor_key).unwrap(),
        height: f.m_height,
        mm_rhs: u256_from_display_hex(&f.m_mm_rhs).unwrap(),
    }
}

fn load() -> Vec<Vector> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/block_header_v2.json");
    let text = std::fs::read_to_string(path).expect("vector file");
    serde_json::from_str::<File>(&text).expect("parse").headers
}

#[test]
fn all_vectors_reproduce() {
    let vectors = load();
    assert_eq!(vectors.len(), 5);
    for v in &vectors {
        let h = header_from(&v.fields);
        let ser = h.serialize();
        assert_eq!(hex::encode(ser), v.serialized, "{}: serialized", v.name);
        assert_eq!(HeaderV2::deserialize(&ser).unwrap(), h, "{}: roundtrip", v.name);

        let c = h.hash_components();
        assert_eq!(hex::encode(c.xor_key_hash), v.xor_key_hash, "{}: xor_key_hash", v.name);
        assert_eq!(hex::encode(c.h1), v.h1, "{}: h1", v.name);
        assert_eq!(hex::encode(c.h2), v.h2, "{}: h2", v.name);
        assert_eq!(hex::encode(c.hash1), v.blake2b_1, "{}: blake2b_1", v.name);
        assert_eq!(c.asic_profile, v.asic_profile, "{}: profile", v.name);
        assert_eq!(hex::encode(&c.asic_input), v.asic_input, "{}: asic_input", v.name);
        assert_eq!(hex::encode(c.hash2), v.blake2b_2, "{}: blake2b_2", v.name);
        assert_eq!(hex::encode(c.mask), v.mask, "{}: mask", v.name);
        assert_eq!(hex::encode(c.result), v.block_hash, "{}: block_hash", v.name);
        assert_eq!(h.pow_hash_hex(), v.block_hash, "{}: pow_hash_hex", v.name);
        assert_eq!(display_hex(&h.pow_hash()), v.block_hash, "{}: pow_hash", v.name);
    }
}

#[test]
fn profile0_is_sia_header() {
    let v = &load()[0];
    assert_eq!(v.asic_profile, 0);
    let h = header_from(&v.fields);
    let c = h.hash_components();
    let mut arbtx = vec![0u8; 4];
    arbtx.extend_from_slice(&c.h2);
    arbtx.extend_from_slice(&h.extranonce);
    assert_eq!(blake2b_256(&arbtx), c.hash1);
    // The parent-id slot carries the hidden previous block hash, not the hash itself.
    let mut sia = Vec::new();
    sia.extend_from_slice(&prevblock_hidden(&h.prev_block));
    sia.extend_from_slice(&h.nonce.to_le_bytes());
    sia.extend_from_slice(&h.nonce2.to_le_bytes());
    sia.extend_from_slice(&h.time_offset.to_le_bytes());
    sia.extend_from_slice(&h.nonce3.to_le_bytes());
    sia.extend_from_slice(&c.hash1);
    assert_eq!(sia, c.asic_input);
}
