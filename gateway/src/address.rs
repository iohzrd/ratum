//! Addresses to output scripts, as the C gateway's `addr_2_output_script`: bech32 version 0
//! (20- or 32-byte program) and bech32m version 1 (32-byte program) under the `bc`, `tb` and
//! `bcrt` prefixes, and base58check P2PKH (version 0 or 111) and P2SH (version 5 or 196). No
//! network check: an address of any of these chains is accepted whatever chain the node is on.

use bech32::Hrp;
use ratum::bitcoin::opcode::{
    OP_0, OP_1, OP_16, OP_CHECKSIG, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160, OP_N_BASE,
    OP_RETURN,
};

/// `base58Prefixes[PUBKEY_ADDRESS]` and `[SCRIPT_ADDRESS]` (`kernel/chainparams.cpp`):
/// mainnet, then the value testnet, signet and regtest share.
const PUBKEY_ADDRESS_MAIN: u8 = 0;
const PUBKEY_ADDRESS_TEST: u8 = 111;
const SCRIPT_ADDRESS_MAIN: u8 = 5;
const SCRIPT_ADDRESS_TEST: u8 = 196;

/// A base58check payload: the one-byte version prefix and a HASH160.
const HASH160_SIZE: usize = 20;
const BASE58_PAYLOAD_SIZE: usize = 1 + HASH160_SIZE;

/// `OP_DUP OP_HASH160 <20> ... OP_EQUALVERIFY OP_CHECKSIG`, and where the HASH160 sits in it.
const P2PKH_SIZE: usize = 25;
const P2PKH_HASH_AT: std::ops::Range<usize> = 3..3 + HASH160_SIZE;
/// `OP_HASH160 <20> ... OP_EQUAL`, and where the HASH160 sits in it.
const P2SH_SIZE: usize = 23;
const P2SH_HASH_AT: std::ops::Range<usize> = 2..2 + HASH160_SIZE;
/// A witness version 1 output carries only the 32-byte P2TR program.
const WITNESS_V1_PROGRAM_SIZE: usize = 32;
/// The witness program lengths a witness version 0 output may carry: the 20-byte P2WPKH
/// program and the 32-byte P2WSH one, which is as long as the P2TR program.
const WITNESS_V0_PROGRAM_SIZES: [usize; 2] = [HASH160_SIZE, WITNESS_V1_PROGRAM_SIZE];
/// The witness program lengths BIP141 allows at all.
const WITNESS_PROGRAM_SIZES: std::ops::RangeInclusive<usize> = 2..=40;
/// A witness output's script before its program: the version opcode and the program length.
const WITNESS_SCRIPT_PREFIX_SIZE: usize = 2;

/// The shortest string `addr_2_output_script` examines at all.
const MIN_ADDRESS_CHARS: usize = 16;
/// The longest string [`to_output_script`] is called on, a bound on the work a stratum
/// username or a configured address can cost before it is decoded. Every accepted form is
/// far shorter: the longest is a 62-character bech32m P2TR address.
pub const MAX_ADDRESS_CHARS: usize = 128;

/// The output script an address pays to, or `None` when it is not one of the accepted forms.
pub fn to_output_script(addr: &str) -> Option<Vec<u8>> {
    if addr.len() < MIN_ADDRESS_CHARS {
        return None;
    }
    let lower = addr.to_ascii_lowercase();
    if lower.starts_with("bc") || lower.starts_with("tb") {
        let hrp = if lower.starts_with('t') {
            Hrp::parse("tb").ok()?
        } else if lower.starts_with("bcrt1") {
            Hrp::parse("bcrt").ok()?
        } else {
            Hrp::parse("bc").ok()?
        };
        let (found_hrp, version, program) = bech32::segwit::decode(addr).ok()?;
        if found_hrp != hrp {
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

/// The opcode a witness program's version is written as: `OP_0` for version 0, `OP_1`
/// through `OP_16` above it (`CScript() << CScript::EncodeOP_N(version)`).
fn witness_version_opcode(version: u8) -> u8 {
    if version == 0 { OP_0 } else { OP_N_BASE + version }
}

pub fn is_valid(addr: &str) -> bool {
    to_output_script(addr).is_some()
}

/// The address part of a stratum username: everything before the first `.` or `~`.
pub fn username_address(username: &str) -> &str {
    let end = username.find(['.', '~']).unwrap_or(username.len());
    &username[..end]
}

/// Whether a username begins with an address a coinbase output can pay.
pub fn username_is_payable(username: &str) -> bool {
    let a = username_address(username);
    !a.is_empty() && a.len() < MAX_ADDRESS_CHARS && is_valid(a)
}

/// The display form of an output script (`output_script_2_addr`): mainnet prefixes whatever
/// the chain, `OP_RETURN` for a data output, `UNKNOWN` otherwise.
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
        // A witness version above 1.
        assert!(!is_valid("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs"));
    }

    #[test]
    fn username_forms() {
        assert!(username_is_payable("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
        assert!(username_is_payable("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4.worker"));
        assert!(username_is_payable("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4~mod"));
        assert!(!username_is_payable("lazyminer.worker"));
        assert!(!username_is_payable(".worker"));
        assert_eq!(username_address("a.b~c"), "a");
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
