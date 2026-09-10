use bech32::Hrp;
use ratum::bitcoin::opcode::{
    OP_0, OP_1, OP_16, OP_CHECKSIG, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160, OP_N_BASE,
    OP_RETURN,
};

const PUBKEY_ADDRESS_MAIN: u8 = 0;
const PUBKEY_ADDRESS_TEST: u8 = 111;
const SCRIPT_ADDRESS_MAIN: u8 = 5;
const SCRIPT_ADDRESS_TEST: u8 = 196;

const HASH160_SIZE: usize = 20;
const BASE58_PAYLOAD_SIZE: usize = 1 + HASH160_SIZE;

const P2PKH_SIZE: usize = 25;
const P2PKH_HASH_AT: std::ops::Range<usize> = 3..3 + HASH160_SIZE;
const P2SH_SIZE: usize = 23;
const P2SH_HASH_AT: std::ops::Range<usize> = 2..2 + HASH160_SIZE;
const WITNESS_V1_PROGRAM_SIZE: usize = 32;
const WITNESS_V0_PROGRAM_SIZES: [usize; 2] = [HASH160_SIZE, WITNESS_V1_PROGRAM_SIZE];
const WITNESS_PROGRAM_SIZES: std::ops::RangeInclusive<usize> = 2..=40;
const WITNESS_SCRIPT_PREFIX_SIZE: usize = 2;

const ADDRESS_CHARS: std::ops::Range<usize> = 16..128;

pub fn to_output_script(addr: &str) -> Option<Vec<u8>> {
    if !ADDRESS_CHARS.contains(&addr.len()) {
        return None;
    }
    let lower = addr.to_ascii_lowercase();
    if let Some(expected) = segwit_hrp(&lower) {
        let (found_hrp, version, program) = bech32::segwit::decode(addr).ok()?;
        if found_hrp != Hrp::parse(expected).ok()? {
            return None;
        }
        let v = version.to_u8();
        let ok = (v == 0 && WITNESS_V0_PROGRAM_SIZES.contains(&program.len()))
            || (v == 1 && program.len() == WITNESS_V1_PROGRAM_SIZE);
        if !ok {
            return None;
        }
        let mut script = Vec::with_capacity(WITNESS_SCRIPT_PREFIX_SIZE + program.len());
        script.push(witness_version_opcode(v));
        script.push(program.len() as u8);
        script.extend_from_slice(&program);
        return Some(script);
    }
    let decoded = bs58::decode(addr).with_check(None).into_vec().ok()?;
    if decoded.len() != BASE58_PAYLOAD_SIZE {
        return None;
    }
    let (version, hash) = (decoded[0], &decoded[1..]);
    match version {
        PUBKEY_ADDRESS_MAIN | PUBKEY_ADDRESS_TEST => {
            let mut s = vec![OP_DUP, OP_HASH160, HASH160_SIZE as u8];
            s.extend_from_slice(hash);
            s.extend_from_slice(&[OP_EQUALVERIFY, OP_CHECKSIG]);
            Some(s)
        }
        SCRIPT_ADDRESS_MAIN | SCRIPT_ADDRESS_TEST => {
            let mut s = vec![OP_HASH160, HASH160_SIZE as u8];
            s.extend_from_slice(hash);
            s.push(OP_EQUAL);
            Some(s)
        }
        _ => None,
    }
}

fn segwit_hrp(lower: &str) -> Option<&'static str> {
    if lower.starts_with("bcrt1") {
        Some("bcrt")
    } else if lower.starts_with("tb1") {
        Some("tb")
    } else if lower.starts_with("bc1") {
        Some("bc")
    } else {
        None
    }
}

fn witness_version_opcode(version: u8) -> u8 {
    if version == 0 { OP_0 } else { OP_N_BASE + version }
}

pub fn is_valid(addr: &str) -> bool {
    to_output_script(addr).is_some()
}

pub fn output_script_to_display(script: &[u8]) -> String {
    if script.first() == Some(&OP_RETURN) {
        return "OP_RETURN".to_string();
    }
    if script.len() == P2SH_SIZE
        && script[0] == OP_HASH160
        && script[1] == HASH160_SIZE as u8
        && script[P2SH_SIZE - 1] == OP_EQUAL
    {
        return base58check(SCRIPT_ADDRESS_MAIN, &script[P2SH_HASH_AT]);
    }
    if script.len() == P2PKH_SIZE
        && script[0] == OP_DUP
        && script[1] == OP_HASH160
        && script[2] == HASH160_SIZE as u8
    {
        return base58check(PUBKEY_ADDRESS_MAIN, &script[P2PKH_HASH_AT]);
    }
    let shortest_witness = WITNESS_SCRIPT_PREFIX_SIZE + WITNESS_PROGRAM_SIZES.start();
    if script.len() >= shortest_witness
        && (script[0] == OP_0 || (OP_1..=OP_16).contains(&script[0]))
    {
        let version = if script[0] == OP_0 { 0 } else { script[0] - OP_N_BASE };
        let len = script[1] as usize;
        if WITNESS_PROGRAM_SIZES.contains(&len)
            && script.len() == WITNESS_SCRIPT_PREFIX_SIZE + len
            && let (Ok(hrp), Ok(v)) = (Hrp::parse("bc"), bech32::Fe32::try_from(version))
            && let Ok(s) = bech32::segwit::encode(hrp, v, &script[WITNESS_SCRIPT_PREFIX_SIZE..])
        {
            return s;
        }
    }
    "UNKNOWN".to_string()
}

fn base58check(version: u8, hash: &[u8]) -> String {
    let mut payload = Vec::with_capacity(BASE58_PAYLOAD_SIZE);
    payload.push(version);
    payload.extend_from_slice(hash);
    bs58::encode(payload).with_check().into_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_address_forms_the_gateway_accepts() {
        let s = to_output_script("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
        assert_eq!(s.len(), 22);
        assert_eq!(&s[..2], &[0x00, 0x14]);
        let s = to_output_script("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080").unwrap();
        assert_eq!(s.len(), 22);
        let s = to_output_script("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx").unwrap();
        assert_eq!(s.len(), 22);
        let s = to_output_script("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0")
            .unwrap();
        assert_eq!(s.len(), 34);
        assert_eq!(s[0], 0x51);
        let s = to_output_script("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2").unwrap();
        assert_eq!(s.len(), 25);
        assert_eq!(s[0], 0x76);
        let s = to_output_script("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy").unwrap();
        assert_eq!(s.len(), 23);
        assert_eq!(s[0], 0xa9);
    }

    #[test]
    fn refuses_what_it_should() {
        assert!(!is_valid("lazyminer"));
        assert!(!is_valid(""));
        assert!(!is_valid("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"));
        assert!(!is_valid("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs"));
    }

    #[test]
    fn displays_scripts() {
        let s = to_output_script("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
        assert_eq!(output_script_to_display(&s), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let s = to_output_script("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2").unwrap();
        assert_eq!(output_script_to_display(&s), "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
        assert_eq!(output_script_to_display(&[0x6a, 0x01, 0x00]), "OP_RETURN");
        assert_eq!(output_script_to_display(&[0x51]), "UNKNOWN");
    }
}
