use bytes::Buf as _;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Truncated(pub &'static str);

pub struct Cursor<'a> {
    full: &'a [u8],
    rest: &'a [u8],
}

impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Cursor { full: data, rest: data }
    }

    pub fn pos(&self) -> usize {
        self.full.len() - self.rest.len()
    }

    pub fn rest(&self) -> &'a [u8] {
        self.rest
    }

    pub fn at_end(&self) -> bool {
        self.rest.is_empty()
    }

    fn peek(&self) -> Option<u8> {
        self.rest.first().copied()
    }

    pub fn peek2(&self) -> Option<(u8, u8)> {
        Some((*self.rest.first()?, *self.rest.get(1)?))
    }

    pub fn skip_if(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.rest.advance(1);
            true
        } else {
            false
        }
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
