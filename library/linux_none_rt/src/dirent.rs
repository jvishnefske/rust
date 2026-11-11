//! Parsing the `struct linux_dirent64` records `getdents64` fills a buffer
//! with.

/// One directory entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    pub ino: u64,
    /// `DT_*`, or `DT_UNKNOWN` (0) if the filesystem does not say
    pub d_type: u8,
    /// without the terminating NUL
    pub name: &'a [u8],
}

pub const DT_UNKNOWN: u8 = 0;
pub const DT_FIFO: u8 = 1;
pub const DT_CHR: u8 = 2;
pub const DT_DIR: u8 = 4;
pub const DT_BLK: u8 = 6;
pub const DT_REG: u8 = 8;
pub const DT_LNK: u8 = 10;
pub const DT_SOCK: u8 = 12;

// d_ino: u64, d_off: i64, d_reclen: u16, d_type: u8, d_name: [u8]
const NAME: usize = 19;

/// The entries in the first `len` bytes `getdents64` wrote. Stops at the
/// first malformed record.
pub struct Iter<'a> {
    buf: &'a [u8],
}

impl<'a> Iter<'a> {
    pub fn new(buf: &'a [u8]) -> Iter<'a> {
        Iter { buf }
    }

    /// Bytes not parsed yet.
    pub fn remaining(&self) -> usize {
        self.buf.len()
    }
}

impl<'a> Iterator for Iter<'a> {
    type Item = Entry<'a>;

    fn next(&mut self) -> Option<Entry<'a>> {
        let b = self.buf;
        if b.len() < NAME {
            return None;
        }
        let reclen = u16::from_ne_bytes([b[16], b[17]]) as usize;
        if reclen <= NAME || reclen > b.len() {
            self.buf = &[];
            return None;
        }
        let rec = &b[..reclen];
        let name = &rec[NAME..];
        let name = &name[..name.iter().position(|&c| c == 0).unwrap_or(name.len())];
        let ino = u64::from_ne_bytes(rec[..8].try_into().unwrap());
        self.buf = &b[reclen..];
        Some(Entry { ino, d_type: rec[18], name })
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Any buffer parses without panicking, every name lies inside its own
    /// record, and the parser always makes progress.
    #[kani::proof]
    // Bounded to keep the proof tractable: a 24-byte buffer holds at most
    // one record, and the name scan (at most 24 - NAME bytes) is the
    // longest loop.
    #[kani::unwind(8)]
    fn parse_any_buffer() {
        let buf: [u8; 24] = kani::any();
        let len: usize = kani::any_where(|&l| l <= 24);
        let mut it = Iter::new(&buf[..len]);
        let mut n = 0;
        while let Some(e) = it.next() {
            // (no NUL in the name: that is what `position` stops at)
            assert!(e.name.len() <= len - NAME);
            n += 1;
            assert!(n <= len / (NAME + 1));
        }
    }
}
