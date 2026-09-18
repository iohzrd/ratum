//! Script opcodes, the pushes a coinbase scriptSig is assembled from and read back through, and the
//! consensus limit on the size of an output script.

use bytes::BufMut as _;

pub mod opcode {
    pub(crate) const OP_0: u8 = 0x00;
    pub(crate) const OP_PUSHDATA1: u8 = 0x4c;
    pub(crate) const OP_PUSHDATA2: u8 = 0x4d;
    pub(crate) const OP_PUSHDATA4: u8 = 0x4e;
    pub(crate) const OP_1: u8 = 0x51;
    pub(crate) const OP_16: u8 = 0x60;
    pub const OP_RETURN: u8 = 0x6a;
    pub(crate) const OP_DUP: u8 = 0x76;
    pub(crate) const OP_EQUAL: u8 = 0x87;
    pub(crate) const OP_EQUALVERIFY: u8 = 0x88;
    pub(crate) const OP_HASH160: u8 = 0xa9;
    pub(crate) const OP_CHECKSIG: u8 = 0xac;
    pub(crate) const OP_CHECKSIGVERIFY: u8 = 0xad;
    pub(crate) const OP_CHECKMULTISIG: u8 = 0xae;
    pub(crate) const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;

    pub(crate) const MAX_DIRECT_PUSH: usize = OP_PUSHDATA1 as usize - 1;
    pub(crate) const MAX_DIRECT_PUSH_OPCODE: u8 = MAX_DIRECT_PUSH as u8;

    pub(crate) const OP_N_BASE: u8 = OP_1 - 1;
}

pub const MAX_OUTPUT_SCRIPT_SIZE: usize = 34;
pub(crate) const MAX_OUTPUT_DATA_SIZE: usize = 83;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScriptPush<'a> {
    pub data_at: usize,
    pub data: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ScriptOp<'a> {
    pub opcode: u8,
    pub push: Option<ScriptPush<'a>>,
}

pub(crate) fn script_ops(script: &[u8]) -> impl Iterator<Item = ScriptOp<'_>> {
    ScriptOps { script, at: 0 }
}

struct ScriptOps<'a> {
    script: &'a [u8],
    at: usize,
}

impl<'a> Iterator for ScriptOps<'a> {
    type Item = ScriptOp<'a>;

    fn next(&mut self) -> Option<ScriptOp<'a>> {
        let opcode = *self.script.get(self.at)?;
        let length_bytes = match opcode {
            0x01..=opcode::MAX_DIRECT_PUSH_OPCODE => 0,
            opcode::OP_PUSHDATA1 => 1,
            opcode::OP_PUSHDATA2 => 2,
            opcode::OP_PUSHDATA4 => 4,
            _ => {
                self.at += 1;
                return Some(ScriptOp { opcode, push: None });
            }
        };
        let after_opcode = self.at + 1;
        let (data_at, len) = if length_bytes == 0 {
            (after_opcode, usize::from(opcode))
        } else {
            let field = self.script.get(after_opcode..after_opcode + length_bytes)?;
            let len = field.iter().rev().fold(0usize, |n, b| (n << 8) | usize::from(*b));
            (after_opcode + length_bytes, len)
        };
        let end = data_at.checked_add(len)?;
        let data = self.script.get(data_at..end)?;
        self.at = end;
        Some(ScriptOp { opcode, push: Some(ScriptPush { data_at, data }) })
    }
}

pub fn script_pushes(script: &[u8]) -> Vec<ScriptPush<'_>> {
    script_ops(script).filter_map(|op| op.push).collect()
}

pub fn output_script_size_is_valid(script: &[u8]) -> bool {
    if script.is_empty() {
        return true;
    }
    let limit =
        if script[0] == opcode::OP_RETURN { MAX_OUTPUT_DATA_SIZE } else { MAX_OUTPUT_SCRIPT_SIZE };
    script.len() <= limit
}

/// The BIP34 height push: OP_0, OP_1..OP_16, or a minimally encoded little-endian number.
pub(crate) fn height_push(height: u32) -> Vec<u8> {
    const SIGN_BIT: u8 = 0x80;
    const SMALL_INT_MAX: u32 = (opcode::OP_16 - opcode::OP_N_BASE) as u32;

    match height {
        0 => vec![opcode::OP_0],
        1..=SMALL_INT_MAX => vec![opcode::OP_N_BASE + height as u8],
        h => {
            let mut bytes = Vec::new();
            let mut v = h;
            while v > 0 {
                bytes.push(v as u8);
                v >>= u8::BITS;
            }
            if bytes.last().is_some_and(|b| b & SIGN_BIT != 0) {
                bytes.push(0);
            }
            let mut out = vec![bytes.len() as u8];
            out.extend_from_slice(&bytes);
            out
        }
    }
}

pub(crate) fn encode_push(data: &[u8]) -> Vec<u8> {
    debug_assert!(u8::try_from(data.len()).is_ok());
    let mut out = Vec::with_capacity(2 + data.len());
    if data.len() > opcode::MAX_DIRECT_PUSH {
        out.put_u8(opcode::OP_PUSHDATA1);
    }
    out.put_u8(data.len() as u8);
    out.put_slice(data);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn height_pushes_match_bip34() {
        assert_eq!(height_push(0), vec![0x00]);
        assert_eq!(height_push(1), vec![0x51]);
        assert_eq!(height_push(16), vec![0x60]);
        assert_eq!(height_push(17), vec![0x01, 0x11]);
        assert_eq!(height_push(128), vec![0x02, 0x80, 0x00]);
        assert_eq!(height_push(840_000), vec![0x03, 0x40, 0xd1, 0x0c]);
    }

    #[test]
    fn encodes_a_direct_push_and_a_pushdata1_push() {
        assert_eq!(encode_push(&[1, 2]), vec![2, 1, 2]);
        let long = [7u8; 80];
        let p = encode_push(&long);
        assert_eq!(&p[..2], &[0x4c, 80]);
        assert_eq!(p.len(), 82);
    }

    #[test]
    fn output_script_sizes_follow_the_consensus_rule() {
        assert!(output_script_size_is_valid(&[0xab; 34]));
        assert!(!output_script_size_is_valid(&[0xab; 35]));

        let mut data = vec![opcode::OP_RETURN];
        data.extend_from_slice(&[0xcd; 82]);
        assert_eq!(data.len(), 83);
        assert!(output_script_size_is_valid(&data));
        data.push(0xcd);
        assert!(!output_script_size_is_valid(&data));

        assert!(output_script_size_is_valid(&[]));
    }

    #[test]
    fn every_address_type_fits_but_a_future_witness_program_need_not() {
        for len in [22usize, 23, 25, 34] {
            assert!(output_script_size_is_valid(&vec![0x00; len]), "{len} bytes");
        }

        let mut witness_unknown = vec![0x52, 40];
        witness_unknown.extend_from_slice(&[0xef; 40]);
        assert_eq!(witness_unknown.len(), 42);
        assert!(
            witness_unknown.len()
                <= crate::datum::messages::coinbaser::MAX_COINBASER_OUTPUT_SCRIPT_LEN
        );
        assert!(!output_script_size_is_valid(&witness_unknown));
    }

    #[test]
    fn reads_script_pushes() {
        let script = [0x03, b'a', b'b', b'c', 0x4c, 0x02, b'd', b'e', 0x6a, 0xff];
        let pushes = script_pushes(&script);
        assert_eq!(pushes.len(), 2);
        assert_eq!(pushes[0], ScriptPush { data_at: 1, data: b"abc" });
        assert_eq!(pushes[1], ScriptPush { data_at: 6, data: b"de" });

        assert!(script_pushes(&[0x05, 0x01, 0x02]).is_empty());
    }

    #[test]
    fn skips_non_pushdata_opcodes_such_as_a_low_bip34_height() {
        let script = [0x56, 0x03, b'a', b'b', b'c', 0x02, b'd', b'e'];
        let pushes = script_pushes(&script);
        assert_eq!(pushes.len(), 2);
        assert_eq!(pushes[0], ScriptPush { data_at: 2, data: b"abc" });
        assert_eq!(pushes[1], ScriptPush { data_at: 6, data: b"de" });

        let with_gap = [0x56, 0x01, b'x', 0x51, 0x01, b'y'];
        assert_eq!(
            script_pushes(&with_gap),
            vec![ScriptPush { data_at: 2, data: b"x" }, ScriptPush { data_at: 5, data: b"y" }]
        );
    }
}
