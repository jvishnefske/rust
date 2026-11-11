//! Looking a user up in `/etc/passwd`, for `env::home_dir` when `$HOME` is
//! not set: what `getpwuid_r` does with only the `files` database.

/// The home directory (the sixth field) of the first entry for `uid` in
/// `passwd`, an `/etc/passwd` file.
pub fn home_dir(passwd: &[u8], uid: u32) -> Option<&[u8]> {
    passwd.split(|&b| b == b'\n').find_map(|line| entry_home(line, uid))
}

/// The home directory in `line`, an entry
/// (`name:password:uid:gid:gecos:dir:shell`), if it is `uid`'s.
fn entry_home(line: &[u8], uid: u32) -> Option<&[u8]> {
    let mut fields = line.split(|&b| b == b':');
    let (Some(id), Some(dir)) = (fields.nth(2), fields.nth(2)) else { return None };
    (parse_uid(id) == Some(uid)).then_some(dir)
}

/// A decimal uid; None if it is not one or does not fit.
pub(crate) fn parse_uid(s: &[u8]) -> Option<u32> {
    if s.is_empty() || s.len() > 10 {
        return None;
    }
    let mut n: u32 = 0;
    for &d in s {
        if !d.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add((d - b'0') as u32)?;
    }
    Some(n)
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Any entry parses without panicking, and the home directory found is
    /// a field of it: after the uid, with no `:` in it. (Splitting the file
    /// into lines is `slice::split`'s.)
    #[kani::proof]
    // Bounded to keep the proof tractable: 8 bytes hold the shortest entry
    // with a home directory (`::0:::/h`), and every loop scans at most each
    // byte once.
    #[kani::unwind(10)]
    fn entry_home_of_any_line() {
        let buf: [u8; 8] = kani::any();
        let len: usize = kani::any_where(|&l| l <= 8);
        let line = &buf[..len];
        if let Some(dir) = entry_home(line, kani::any()) {
            let off = dir.as_ptr() as usize - line.as_ptr() as usize;
            assert!(off >= 5 && off + dir.len() <= len);
            assert!(!dir.contains(&b':'));
        }
    }

    /// Up to four digits parse to their value; anything else with them is
    /// not a uid. (Built from digits rather than by printing a uid: symbolic
    /// division is what makes such a proof slow.)
    #[kani::proof]
    #[kani::unwind(6)]
    fn parse_uid_digits() {
        let s: [u8; 4] = kani::any();
        let len: usize = kani::any_where(|&l| l <= 4);
        let s = &s[..len];
        let want = s.iter().try_fold(0u32, |n, &d| d.is_ascii_digit().then(|| n * 10 + (d - b'0') as u32));
        assert_eq!(parse_uid(s), if len == 0 { None } else { want });
    }
}
