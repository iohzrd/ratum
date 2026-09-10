use ratum::header::*;
use serde_json::Value;

struct Vector {
    name: String,
    header: HeaderV2,
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

fn u128_from_display_hex(s: &str) -> U128 {
    let mut v: U128 = hex::decode(s).expect("hex").try_into().expect("16 bytes");
    v.reverse();
    v
}

fn u256(v: &Value, key: &str) -> U256 {
    u256_from_display_hex(v[key].as_str().expect(key)).expect(key)
}

fn u128(v: &Value, key: &str) -> U128 {
    u128_from_display_hex(v[key].as_str().expect(key))
}

fn num(v: &Value, key: &str) -> i64 {
    v[key].as_i64().expect(key)
}

fn text(v: &Value, key: &str) -> String {
    v[key].as_str().expect(key).to_string()
}

fn load() -> Vec<Vector> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/block_header_v2.json");
    let text_of_file = std::fs::read_to_string(path).expect("vector file");
    let file: Value = serde_json::from_str(&text_of_file).expect("parse");
    file["headers"]
        .as_array()
        .expect("headers")
        .iter()
        .map(|v| {
            let f = &v["fields"];
            Vector {
                name: text(v, "name"),
                header: HeaderV2 {
                    version: num(f, "nVersion") as i32,
                    prev_block: u256(f, "hashPrevBlock"),
                    merkle_root: u256(f, "hashMerkleRoot"),
                    time: num(f, "nTime") as u32,
                    bits: num(f, "nBits") as u32,
                    nonce: num(f, "nNonce") as u32,
                    nonce2: num(f, "m_nonce2") as u32,
                    nonce3: num(f, "m_nonce3") as u32,
                    extranonce: u128(f, "m_extranonce"),
                    time_offset: num(f, "m_time_offset") as u32,
                    txcount: num(f, "m_txcount") as u16,
                    flags: num(f, "m_flags") as u8,
                    xor_key_mask_clear_bits: num(f, "m_xor_key_mask_clear_bits") as u8,
                    xor_key: u128(f, "m_xor_key"),
                    height: num(f, "m_height") as i32,
                    mm_rhs: u256(f, "m_mm_rhs"),
                },
                serialized: text(v, "serialized"),
                h1: text(v, "h1"),
                xor_key_hash: text(v, "xor_key_hash"),
                h2: text(v, "h2"),
                blake2b_1: text(v, "blake2b_1"),
                blake2b_2: text(v, "blake2b_2"),
                mask: text(v, "mask"),
                block_hash: text(v, "block_hash"),
                asic_profile: num(v, "asic_profile") as u8,
                asic_input: text(v, "asic_input"),
            }
        })
        .collect()
}

#[test]
fn all_vectors_reproduce() {
    let vectors = load();
    assert_eq!(vectors.len(), 5);
    for v in &vectors {
        let h = &v.header;
        let ser = h.serialize();
        assert_eq!(hex::encode(ser), v.serialized, "{}: serialized", v.name);
        assert_eq!(HeaderV2::deserialize(&ser).unwrap(), *h, "{}: roundtrip", v.name);

        assert_eq!(
            hex::encode(xor_key_hash(&h.xor_key)),
            v.xor_key_hash,
            "{}: xor_key_hash",
            v.name
        );

        let pre = h.precompute();
        let mut hook = [0u8; H2_PREIMAGE_SIZE];
        hook[..32].copy_from_slice(&hex::decode(&v.h1).expect("h1 hex"));
        hook[H2_PREIMAGE_SIZE - 32..].copy_from_slice(&h.mm_rhs);
        assert_eq!(
            tagged_sha256("Merge-mining hook", &hook),
            pre.h2,
            "{}: h1 is the first stage h2 commits to",
            v.name
        );
        assert_eq!(hex::encode(pre.h2), v.h2, "{}: h2", v.name);
        assert_eq!(hex::encode(pre.hash1), v.blake2b_1, "{}: blake2b_1", v.name);
        assert_eq!(hex::encode(pre.mask), v.mask, "{}: mask", v.name);
        assert_eq!(h.asic_profile(), v.asic_profile, "{}: profile", v.name);

        let asic_input = h.asic_input_with(&pre.hash1, &pre.h2);
        assert_eq!(hex::encode(&asic_input), v.asic_input, "{}: asic_input", v.name);
        assert_eq!(
            asic_input.len(),
            ASIC_INPUT_LEN[usize::from(v.asic_profile)],
            "{}: asic_input length",
            v.name
        );

        let (pow, block) = h.pow_and_block_hash();
        assert_eq!(hex::encode(pow), v.blake2b_2, "{}: blake2b_2", v.name);
        assert_eq!(hex::encode(block), v.block_hash, "{}: block_hash", v.name);
        assert_eq!(blake2b_256(&asic_input), pow, "{}: pow is blake2b of the asic input", v.name);
    }
}

#[test]
fn profile0_is_sia_header() {
    let vectors = load();
    let v = &vectors[0];
    assert_eq!(v.asic_profile, 0);
    let h = &v.header;
    let pre = h.precompute();

    let mut leaf = vec![0u8; WORK_ROOT_H2_OFFSET];
    leaf.extend_from_slice(&pre.h2);
    leaf.extend_from_slice(&h.extranonce);
    assert_eq!(leaf.len(), WORK_ROOT_LEAF_SIZE);
    assert_eq!(blake2b_256(&leaf), pre.hash1);

    let mut sia = Vec::new();
    sia.extend_from_slice(&prevblock_hidden(&h.prev_block));
    sia.extend_from_slice(&h.nonce.to_le_bytes());
    sia.extend_from_slice(&h.nonce2.to_le_bytes());
    sia.extend_from_slice(&h.time_offset.to_le_bytes());
    sia.extend_from_slice(&h.nonce3.to_le_bytes());
    sia.extend_from_slice(&pre.hash1);
    assert_eq!(sia, h.asic_input_with(&pre.hash1, &pre.h2));
}

#[test]
fn display_hex_round_trips_through_the_internal_order() {
    for v in &load() {
        let display = u256_to_display_hex(&v.header.prev_block);
        assert_eq!(u256_from_display_hex(&display).unwrap(), v.header.prev_block, "{}", v.name);
    }
}
