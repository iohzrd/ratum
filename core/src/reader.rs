//! A cursor over a byte slice. Every read either returns its field or reports which field the input
//! ran out of bytes in, so a decoder names the field a short message ends in rather than panicking.

use bytes::Buf as _;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Truncated(pub &'static str);

pub struct ByteReader<'a> {
    full: &'a [u8],
    rest: &'a [u8],
}

impl<'a> ByteReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        ByteReader { full: data, rest: data }
    }

    pub fn pos(&self) -> usize {
        self.full.len() - self.rest.len()
    }

    pub fn rest(&self) -> &'a [u8] {
        self.rest
    }

    pub(crate) fn at_end(&self) -> bool {
        self.rest.is_empty()
    }

    pub(crate) fn peek2(&self) -> Option<(u8, u8)> {
        Some((*self.rest.first()?, *self.rest.get(1)?))
    }

    pub fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], Truncated> {
        if self.rest.len() < n {
            return Err(Truncated(what));
        }
        let taken: &'a [u8] = &self.rest[..n];
        self.rest.advance(n);
        Ok(taken)
    }

    pub fn advance(&mut self, n: usize, what: &'static str) -> Result<(), Truncated> {
        self.take(n, what).map(|_| ())
    }

    pub fn arr<const N: usize>(&mut self, what: &'static str) -> Result<[u8; N], Truncated> {
        Ok(self.take(N, what)?.try_into().expect("N bytes"))
    }

    pub fn u8(&mut self, what: &'static str) -> Result<u8, Truncated> {
        self.rest.try_get_u8().map_err(|_| Truncated(what))
    }

    pub fn u16(&mut self, what: &'static str) -> Result<u16, Truncated> {
        self.rest.try_get_u16_le().map_err(|_| Truncated(what))
    }

    pub fn u32(&mut self, what: &'static str) -> Result<u32, Truncated> {
        self.rest.try_get_u32_le().map_err(|_| Truncated(what))
    }

    pub fn u64(&mut self, what: &'static str) -> Result<u64, Truncated> {
        self.rest.try_get_u64_le().map_err(|_| Truncated(what))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_fields_in_order() {
        let data = [0x27, 0x01, 0x02, 0x03, 0x04, 0x05, 0xaa, 0xbb];
        let mut c = ByteReader::new(&data);
        assert_eq!(c.u8("subcommand").unwrap(), 0x27);
        assert_eq!(c.u8("a").unwrap(), 0x01);
        assert_eq!(c.u32("b").unwrap(), 0x0504_0302);
        assert_eq!(c.pos(), 6);
        assert_eq!(c.rest(), &[0xaa, 0xbb]);
        assert_eq!(c.arr::<2>("c").unwrap(), [0xaa, 0xbb]);
        assert!(c.at_end());
    }

    #[test]
    fn a_short_read_names_the_field() {
        let mut c = ByteReader::new(&[0x01, 0x02]);
        assert_eq!(c.u32("nonce"), Err(Truncated("nonce")));
        assert_eq!(c.u16("half").unwrap(), 0x0201);
    }

    #[test]
    fn an_overflowing_length_is_truncation_not_a_panic() {
        let mut c = ByteReader::new(&[0u8; 4]);
        c.advance(2, "start").unwrap();
        assert_eq!(c.take(usize::MAX, "huge"), Err(Truncated("huge")));
        assert_eq!(c.pos(), 2);
    }

    #[test]
    fn peeking_does_not_advance() {
        let mut c = ByteReader::new(&[0x00, 0x01]);
        assert_eq!(c.peek2(), Some((0x00, 0x01)));
        assert_eq!(c.pos(), 0);
        c.advance(1, "one").unwrap();
        assert_eq!(c.peek2(), None, "one byte left");
        assert_eq!(c.rest(), &[0x01]);
    }
}
