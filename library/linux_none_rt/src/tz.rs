//! Local time, for `localtime_r`: the offset from UTC that a zone gives a
//! time, from its TZif file (RFC 8536) or a POSIX TZ string such as
//! `CST6CDT,M3.2.0,M11.1.0`. A TZif file's transitions end at its last rule
//! change; the TZ string in its footer gives the times after that.

/// The local time type in effect at a time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Local {
    /// Seconds east of UTC.
    pub offset: i32,
    pub isdst: bool,
    /// The abbreviation, such as `CDT`, NUL-padded.
    pub abbr: [u8; 8],
}

impl Local {
    pub const UTC: Local = Local { offset: 0, isdst: false, abbr: *b"UTC\0\0\0\0\0" };

    fn new(offset: i32, isdst: bool, name: &[u8]) -> Local {
        let mut abbr = [0; 8];
        let n = name.len().min(7);
        abbr[..n].copy_from_slice(&name[..n]);
        Local { offset, isdst, abbr }
    }
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn be64(b: &[u8], at: usize) -> Option<i64> {
    Some(i64::from_be_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// The local time type of `t` (seconds since the epoch) in a TZif file.
pub fn tzif(file: &[u8], t: i64) -> Option<Local> {
    if file.get(..4)? != b"TZif" {
        return None;
    }
    let counts = |at: usize| -> Option<[usize; 6]> {
        let mut c = [0; 6];
        for (i, c) in c.iter_mut().enumerate() {
            *c = be32(file, at + 20 + 4 * i)? as usize;
        }
        Some(c)
    };
    // isutcnt, isstdcnt, leapcnt, timecnt, typecnt, charcnt
    let [isut, isstd, leap, times, types, chars] = counts(0)?;
    let v1 = times * 5 + types * 6 + chars + leap * 8 + isstd + isut;
    // version 2 and up repeat the data with 64-bit times, then a footer
    let (data, time_size, [_, _, _, times, types, chars], footer) = if file[4] >= b'2' {
        let at = 44 + v1;
        let c @ [isut, isstd, leap, times, types, chars] = counts(at)?;
        let len = times * 9 + types * 6 + chars + leap * 12 + isstd + isut;
        let footer = file.get(at + 44 + len..)?;
        (at + 44, 8, c, footer.strip_prefix(b"\n").and_then(|f| f.split(|&b| b == b'\n').next()))
    } else {
        (44, 4, [isut, isstd, leap, times, types, chars], None)
    };
    let time = |i: usize| if time_size == 8 { be64(file, data + 8 * i) } else { be32(file, data + 4 * i).map(|v| v as i32 as i64) };
    let idx_at = data + times * time_size;
    let types_at = idx_at + times;
    let chars_at = types_at + types * 6;
    let ttinfo = |i: usize| -> Option<Local> {
        let at = types_at + 6 * i;
        let offset = be32(file, at)? as i32;
        let abbr = file.get(chars_at + *file.get(at + 5)? as usize..chars_at + chars)?;
        let end = abbr.iter().position(|&b| b == 0).unwrap_or(abbr.len());
        Some(Local::new(offset, *file.get(at + 4)? != 0, &abbr[..end]))
    };
    // the last transition at or before t
    let (mut lo, mut hi) = (0, times);
    while lo < hi {
        let mid = (lo + hi) / 2;
        if time(mid)? <= t { lo = mid + 1 } else { hi = mid }
    }
    match lo {
        0 => ttinfo(0),
        n if n == times => match footer.filter(|f| !f.is_empty()) {
            Some(f) => posix(f, t),
            None => ttinfo(*file.get(idx_at + n - 1)? as usize),
        },
        n => ttinfo(*file.get(idx_at + n - 1)? as usize),
    }
}

/// A POSIX TZ string being parsed.
struct Parser<'s>(&'s [u8]);

impl<'s> Parser<'s> {
    fn peek(&self) -> Option<u8> {
        self.0.first().copied()
    }

    fn eat(&mut self, b: u8) -> bool {
        let ate = self.peek() == Some(b);
        if ate {
            self.0 = &self.0[1..];
        }
        ate
    }

    /// `EST`, or quoted, `<+03>`.
    fn name(&mut self) -> Option<&'s [u8]> {
        let (name, rest) = if self.eat(b'<') {
            let end = self.0.iter().position(|&b| b == b'>')?;
            (&self.0[..end], &self.0[end + 1..])
        } else {
            let end = self.0.iter().position(|b| !b.is_ascii_alphabetic()).unwrap_or(self.0.len());
            (&self.0[..end], &self.0[end..])
        };
        self.0 = rest;
        (name.len() >= 3).then_some(name)
    }

    fn num(&mut self) -> Option<i64> {
        let end = self.0.iter().position(|b| !b.is_ascii_digit()).unwrap_or(self.0.len());
        let n = core::str::from_utf8(&self.0[..end]).ok()?.parse().ok()?;
        self.0 = &self.0[end..];
        Some(n)
    }

    /// `[+-]hh[:mm[:ss]]`, in seconds.
    fn time(&mut self) -> Option<i64> {
        let sign = if self.eat(b'-') { -1 } else { self.eat(b'+'); 1 };
        let mut secs = self.num()? * 3600;
        if self.eat(b':') {
            secs += self.num()? * 60;
            if self.eat(b':') {
                secs += self.num()?;
            }
        }
        Some(sign * secs)
    }

    /// A rule's day (`Jn`, `n` or `Mm.w.d`) and time of day, which is 2:00
    /// unless given.
    fn rule(&mut self) -> Option<(Day, i64)> {
        let day = if self.eat(b'J') {
            Day::Julian(self.num()?)
        } else if self.eat(b'M') {
            let m = self.num()?;
            self.eat(b'.').then_some(())?;
            let w = self.num()?;
            self.eat(b'.').then_some(())?;
            Day::Month(m, w, self.num()?)
        } else {
            Day::Zero(self.num()?)
        };
        let time = if self.eat(b'/') { self.time()? } else { 7200 };
        Some((day, time))
    }
}

#[derive(Clone, Copy)]
pub enum Day {
    /// `Jn`: 1 to 365, February 29 never counted.
    Julian(i64),
    /// `n`: 0 to 365, February 29 counted in leap years.
    Zero(i64),
    /// `Mm.w.d`: day d (0 is Sunday) of week w (5 is the last) of month m.
    Month(i64, i64, i64),
}

fn is_leap(y: i64) -> bool {
    y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
}

const MONTH_DAYS: [i64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Days since 1970-01-01 of a date (month 1 to 12), and the inverse.
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468
}

pub fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + (m <= 2) as i64, m, d)
}

/// The day a rule names in year y, in days since the epoch.
pub fn rule_day(y: i64, day: Day) -> i64 {
    let jan1 = days_from_civil(y, 1, 1);
    match day {
        Day::Julian(n) => jan1 + n - 1 + (is_leap(y) && n >= 60) as i64,
        Day::Zero(n) => jan1 + n,
        Day::Month(m, w, d) => {
            let first = days_from_civil(y, m, 1);
            // 1970-01-01 was a Thursday
            let wday = (first + 4).rem_euclid(7);
            let mut day = first + (d - wday).rem_euclid(7) + (w - 1) * 7;
            let len = MONTH_DAYS[(m as usize).clamp(1, 12) - 1] + (m == 2 && is_leap(y)) as i64;
            while day >= first + len {
                day -= 7;
            }
            day
        }
    }
}

/// The local time type of `t` under a POSIX TZ string.
pub fn posix(tz: &[u8], t: i64) -> Option<Local> {
    let mut p = Parser(tz);
    let std_name = p.name()?;
    // TZ offsets are west of UTC
    let std_off = -p.time()?;
    let std = Local::new(std_off as i32, false, std_name);
    let Some(dst_name) = p.name() else { return Some(std) };
    let dst_off = if matches!(p.peek(), Some(b',') | None) { std_off + 3600 } else { -p.time()? };
    let dst = Local::new(dst_off as i32, true, dst_name);
    // the US rules, when none are given
    let (start, end) = if p.eat(b',') {
        let start = p.rule()?;
        p.eat(b',').then_some(())?;
        (start, p.rule()?)
    } else {
        ((Day::Month(3, 2, 0), 7200), (Day::Month(11, 1, 0), 7200))
    };
    let (year, _, _) = civil_from_days((t + std_off).div_euclid(86400));
    // the start is in standard time, the end in daylight time
    let starts = rule_day(year, start.0) * 86400 + start.1 - std_off;
    let ends = rule_day(year, end.0) * 86400 + end.1 - dst_off;
    let in_dst = if starts < ends { starts <= t && t < ends } else { t < ends || starts <= t };
    Some(if in_dst { dst } else { std })
}
