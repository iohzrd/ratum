//! Addresses to output scripts, as the C gateway's `addr_2_output_script`: bech32 version 0
//! (20- or 32-byte program) and bech32m version 1 (32-byte program) under the `bc`, `tb` and
//! `bcrt` prefixes, and base58check P2PKH (version 0 or 111) and P2SH (version 5 or 196). No
//! network check: an address of any of these chains is accepted whatever chain the node is on.

use bech32::Hrp;

/// The output script an address pays to, or `None` when it is not one of the accepted forms.
pub fn to_output_script(addr: &str) -> Option<Vec<u8>> {
    if addr.len() < 16 {
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
        let ok = (v == 0 && (program.len() == 20 || program.len() == 32))
            || (v == 1 && program.len() == 32);
        if !ok {
            return None;
        }
        let mut script = Vec::with_capacity(2 + program.len());
        script.push(if v == 0 { 0x00 } else { 0x50 + v });
        script.push(program.len() as u8);
        script.extend_from_slice(&program);
        return Some(script);
    }
    let decoded = bs58::decode(addr).with_check(None).into_vec().ok()?;
    if decoded.len() != 21 {
        return None;
    }
    let (version, hash) = (decoded[0], &decoded[1..]);
    match version {
        0 | 111 => {
            let mut s = vec![0x76, 0xa9, 0x14];
            s.extend_from_slice(hash);
            s.extend_from_slice(&[0x88, 0xac]);
            Some(s)
        }
        5 | 196 => {
            let mut s = vec![0xa9, 0x14];
            s.extend_from_slice(hash);
            s.push(0x87);
            Some(s)
        }
        _ => None,
    }
}

pub fn is_valid(addr: &str) -> bool {
    to_output_script(addr).is_some()
}

/// The address part of a stratum username: everything before the first `.` or `~`.
pub fn username_address(username: &str) -> &str {
    let end = username.find(['.', '~']).unwrap_or(username.len());
    &username[..end]
}

/// Whether a username begins with an address a coinbase output can pay
/// (`datum_stratum_username_is_payable`).
pub fn username_is_payable(username: &str) -> bool {
    let a = username_address(username);
    !a.is_empty() && a.len() < 128 && is_valid(a)
}

/// The display form of an output script (`output_script_2_addr`): mainnet prefixes whatever
/// the chain, `OP_RETURN` for a data output, `UNKNOWN` otherwise.
pub fn output_script_to_display(script: &[u8]) -> String {
    if script.first() == Some(&0x6a) {
        return "OP_RETURN".to_string();
    }
    if script.len() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87 {
        let mut payload = vec![5u8];
        payload.extend_from_slice(&script[2..22]);
        return bs58::encode(payload).with_check().into_string();
    }
    if script.len() == 25 && script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14 {
        let mut payload = vec![0u8];
        payload.extend_from_slice(&script[3..23]);
        return bs58::encode(payload).with_check().into_string();
    }
    if script.len() >= 4 && (script[0] == 0x00 || (0x51..=0x60).contains(&script[0])) {
        let version = if script[0] == 0x00 { 0 } else { script[0] - 0x50 };
        let len = script[1] as usize;
        if (2..=40).contains(&len)
            && script.len() == 2 + len
            && let (Ok(hrp), Ok(v)) = (Hrp::parse("bc"), bech32::Fe32::try_from(version))
            && let Ok(s) = bech32::segwit::encode(hrp, v, &script[2..])
        {
            return s;
        }
    }
    "UNKNOWN".to_string()
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
