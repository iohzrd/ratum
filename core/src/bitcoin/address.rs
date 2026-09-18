//! Addresses and the output scripts they pay. `to_output_script` decodes P2PKH, P2SH, P2WPKH, P2WSH
//! and P2TR against one chain's prefixes, or against every chain's when no chain is given;
//! `output_script_to_display` is the inverse, in mainnet prefixes, for the status pages.

use super::script::opcode::{
    OP_0, OP_1, OP_16, OP_CHECKSIG, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160, OP_N_BASE,
    OP_RETURN,
};
use bech32::Hrp;

/// The prefixes a chain's addresses carry: the human-readable part of a segwit address and
/// the base58 version bytes of a key hash and a script hash address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefixes {
    pub hrp: &'static str,
    pub pubkey_hash: u8,
    pub script_hash: u8,
}

pub const MAIN: Prefixes = Prefixes { hrp: "bc", pubkey_hash: 0, script_hash: 5 };
/// The prefixes of test, testnet4 and signet addresses.
pub(crate) const TEST: Prefixes = Prefixes { hrp: "tb", pubkey_hash: 111, script_hash: 196 };
pub(crate) const REGTEST: Prefixes = Prefixes { hrp: "bcrt", pubkey_hash: 111, script_hash: 196 };
const EVERY_CHAIN: [Prefixes; 3] = [MAIN, TEST, REGTEST];

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

/// The longest script an address decodes to (P2WSH and P2TR), which the reduced_data limit on
/// an output script admits.
pub const MAX_SCRIPT_LEN: usize = WITNESS_SCRIPT_PREFIX_SIZE + WITNESS_V1_PROGRAM_SIZE;
const _: () = assert!(MAX_SCRIPT_LEN <= super::script::MAX_OUTPUT_SCRIPT_SIZE);

const ADDRESS_CHARS: std::ops::Range<usize> = 16..128;

/// The output script of a P2PKH, P2SH, P2WPKH, P2WSH or P2TR address that carries `chain`'s
/// prefixes; with `chain` none, the prefixes of main, test and regtest are all accepted. Any
/// other text gives none, including a witness version above 1 and a version 1 program of
/// other than 32 bytes, such as the two-byte pay-to-anchor program.
pub fn to_output_script(addr: &str, chain: Option<Prefixes>) -> Option<Vec<u8>> {
    if !ADDRESS_CHARS.contains(&addr.len()) {
        return None;
    }
    let accepted = |p: &Prefixes| chain.is_none_or(|c| c == *p);
    if let Some(prefixes) = segwit_prefixes(addr) {
        if !accepted(prefixes) {
            return None;
        }
        let (found_hrp, version, program) = bech32::segwit::decode(addr).ok()?;
        if found_hrp != Hrp::parse(prefixes.hrp).ok()? {
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
    let carried =
        |byte: fn(&Prefixes) -> u8| EVERY_CHAIN.iter().any(|p| accepted(p) && byte(p) == version);
    if carried(|p| p.pubkey_hash) {
        let mut s = vec![OP_DUP, OP_HASH160, HASH160_SIZE as u8];
        s.extend_from_slice(hash);
        s.extend_from_slice(&[OP_EQUALVERIFY, OP_CHECKSIG]);
        Some(s)
    } else if carried(|p| p.script_hash) {
        let mut s = vec![OP_HASH160, HASH160_SIZE as u8];
        s.extend_from_slice(hash);
        s.push(OP_EQUAL);
        Some(s)
    } else {
        None
    }
}

/// The prefixes of the chain whose segwit human-readable part and separator `addr` begins with,
/// in either case: text that begins so is decoded as bech32 or not at all.
fn segwit_prefixes(addr: &str) -> Option<&'static Prefixes> {
    EVERY_CHAIN.iter().find(|p| {
        addr.get(..p.hrp.len()).is_some_and(|hrp| hrp.eq_ignore_ascii_case(p.hrp))
            && addr.as_bytes().get(p.hrp.len()) == Some(&b'1')
    })
}

/// The form of `addr` the pool credits a miner under. BIP 173 lets a bech32 address be written
/// all in uppercase, which decodes to the same script as its lowercase form, so an address
/// carrying a segwit prefix and no lowercase letter is lowercased; anything else is returned
/// unchanged, a base58 address included, since the case of each of its characters is part of
/// the value it encodes.
pub fn canonical(addr: &str) -> std::borrow::Cow<'_, str> {
    if segwit_prefixes(addr).is_some()
        && addr.bytes().any(|b| b.is_ascii_uppercase())
        && !addr.bytes().any(|b| b.is_ascii_lowercase())
    {
        std::borrow::Cow::Owned(addr.to_ascii_lowercase())
    } else {
        std::borrow::Cow::Borrowed(addr)
    }
}

fn witness_version_opcode(version: u8) -> u8 {
    if version == 0 { OP_0 } else { OP_N_BASE + version }
}

pub fn is_valid(addr: &str, chain: Option<Prefixes>) -> bool {
    to_output_script(addr, chain).is_some()
}

/// The mainnet address `script` pays: "OP_RETURN" for a data output and "UNKNOWN" for a
/// script no address encodes.
pub fn output_script_to_display(script: &[u8]) -> String {
    if script.first() == Some(&OP_RETURN) {
        return "OP_RETURN".to_string();
    }
    if script.len() == P2SH_SIZE
        && script[0] == OP_HASH160
        && script[1] == HASH160_SIZE as u8
        && script[P2SH_SIZE - 1] == OP_EQUAL
    {
        return base58check(MAIN.script_hash, &script[P2SH_HASH_AT]);
    }
    if script.len() == P2PKH_SIZE
        && script[..P2PKH_HASH_AT.start] == [OP_DUP, OP_HASH160, HASH160_SIZE as u8]
        && script[P2PKH_HASH_AT.end..] == [OP_EQUALVERIFY, OP_CHECKSIG]
    {
        return base58check(MAIN.pubkey_hash, &script[P2PKH_HASH_AT]);
    }
    let shortest_witness = WITNESS_SCRIPT_PREFIX_SIZE + WITNESS_PROGRAM_SIZES.start();
    if script.len() >= shortest_witness
        && (script[0] == OP_0 || (OP_1..=OP_16).contains(&script[0]))
    {
        let version = if script[0] == OP_0 { 0 } else { script[0] - OP_N_BASE };
        let len = script[1] as usize;
        if WITNESS_PROGRAM_SIZES.contains(&len)
            && script.len() == WITNESS_SCRIPT_PREFIX_SIZE + len
            && let (Ok(hrp), Ok(v)) = (Hrp::parse(MAIN.hrp), bech32::Fe32::try_from(version))
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
    use crate::bitcoin::script::output_script_size_is_valid;
    use bech32::Fe32;

    #[test]
    fn decodes_every_address_form() {
        let forms = [
            ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 22, 0x00),
            ("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", 22, 0x00),
            ("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", 22, 0x00),
            ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", 34, 0x51),
            ("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", 25, 0x76),
            ("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", 23, 0xa9),
        ];
        for (address, len, first) in forms {
            let s = to_output_script(address, None).unwrap_or_else(|| panic!("{address}"));
            assert_eq!((s.len(), s[0]), (len, first), "{address}");
            assert!(s.len() <= MAX_SCRIPT_LEN && output_script_size_is_valid(&s), "{address}");
        }
        let s = to_output_script("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", None).unwrap();
        assert_eq!(&s[..2], &[0x00, 0x14]);
        assert_eq!(
            to_output_script("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", None),
            Some(s),
            "an uppercase address"
        );
    }

    #[test]
    fn refuses_what_it_should() {
        assert!(!is_valid("lazyminer", None));
        assert!(!is_valid("", None));
        assert!(!is_valid("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", None));
        assert!(!is_valid("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", None));
    }

    #[test]
    fn an_anchor_or_a_witness_version_above_1_is_refused() {
        let segwit = |version: Fe32, program: &[u8]| {
            bech32::segwit::encode(Hrp::parse("bc").unwrap(), version, program).unwrap()
        };
        assert!(!is_valid(&segwit(Fe32::P, &[0x4e, 0x73]), None), "pay to anchor");
        assert!(!is_valid(&segwit(Fe32::Z, &[0x11; 32]), None), "witness version 2");
        assert!(is_valid(&segwit(Fe32::P, &[0x11; 32]), None), "taproot");
    }

    #[test]
    fn an_address_is_accepted_only_with_the_prefixes_of_the_chain_given() {
        let program = [0x5a; HASH160_SIZE];
        let segwit = |hrp| bech32::segwit::encode(Hrp::parse(hrp).unwrap(), Fe32::Q, &program);
        let (main, test, regtest) =
            (segwit("bc").unwrap(), segwit("tb").unwrap(), segwit("bcrt").unwrap());
        let main_key_hash = base58check(MAIN.pubkey_hash, &program);
        let test_script_hash = base58check(TEST.script_hash, &program);
        for address in [&main, &test, &regtest, &main_key_hash, &test_script_hash] {
            assert!(is_valid(address, None), "{address} with no chain given");
        }
        assert!(is_valid(&main, Some(MAIN)));
        assert!(!is_valid(&main, Some(TEST)));
        assert!(!is_valid(&main, Some(REGTEST)));
        assert!(!is_valid(&test, Some(REGTEST)), "a regtest segwit address carries bcrt");
        assert!(is_valid(&regtest, Some(REGTEST)));
        assert!(!is_valid(&regtest, Some(MAIN)));
        assert!(is_valid(&main_key_hash, Some(MAIN)));
        assert!(!is_valid(&main_key_hash, Some(REGTEST)));
        assert!(is_valid(&test_script_hash, Some(TEST)));
        assert!(is_valid(&test_script_hash, Some(REGTEST)), "regtest uses the test base58 bytes");
        assert!(!is_valid(&test_script_hash, Some(MAIN)));
    }

    #[test]
    fn displays_scripts() {
        let address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        assert_eq!(output_script_to_display(&to_output_script(address, None).unwrap()), address);
        let address = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
        assert_eq!(output_script_to_display(&to_output_script(address, None).unwrap()), address);
        assert_eq!(output_script_to_display(&[0x6a, 0x01, 0x00]), "OP_RETURN");
        assert_eq!(output_script_to_display(&[0x51]), "UNKNOWN");
    }

    #[test]
    fn a_script_is_displayed_as_p2pkh_or_p2sh_only_when_it_matches_the_whole_template() {
        let p2pkh = to_output_script("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", None).unwrap();
        let p2sh = to_output_script("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", None).unwrap();
        for (script, tail) in [(&p2pkh, 2), (&p2sh, 1)] {
            for at in script.len() - tail..script.len() {
                let mut other = script.clone();
                other[at] = OP_RETURN;
                assert_eq!(output_script_to_display(&other), "UNKNOWN", "byte {at} replaced");
            }
            for at in 0..script.len() - tail - HASH160_SIZE {
                let mut other = script.clone();
                other[at] ^= 0x01;
                assert_ne!(
                    output_script_to_display(&other),
                    output_script_to_display(script),
                    "byte {at} of the prefix altered"
                );
            }
            let mut longer = script.clone();
            longer.push(OP_CHECKSIG);
            assert_eq!(output_script_to_display(&longer), "UNKNOWN", "a byte past the template");
            assert_eq!(output_script_to_display(&script[..script.len() - 1]), "UNKNOWN");
        }
    }

    #[test]
    fn an_uppercase_bech32_address_is_credited_in_lowercase_and_base58_is_left_as_written() {
        let lower = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let upper = lower.to_ascii_uppercase();
        assert_eq!(canonical(&upper), lower);
        assert_eq!(canonical(lower), lower);
        assert_eq!(
            to_output_script(&canonical(&upper), None),
            to_output_script(&upper, None),
            "the canonical form pays the same script"
        );
        for regtest in [
            "BCRT1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KYGT080",
            "TB1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KXPJZSX",
        ] {
            assert_eq!(canonical(regtest), regtest.to_ascii_lowercase());
        }
        let mixed = "BC1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        assert_eq!(canonical(mixed), mixed, "mixed case is not a bech32 address; left as written");
        let base58 = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
        assert_eq!(canonical(base58), base58);
        let p2sh = "3J98T1WPEZ73CNMQVIECRNYIWRNQRHWNLY";
        assert_eq!(canonical(p2sh), p2sh, "an uppercase base58 string is not lowercased");
        assert_eq!(canonical("LAZYMINER"), "LAZYMINER");
        assert_eq!(canonical("BC"), "BC");
        assert_eq!(canonical(""), "");
    }
}
