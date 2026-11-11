//! printf and the standard streams, for C code in crates: `snprintf` and
//! friends, and `fputs`/`fwrite` to `stdout`/`stderr`, unbuffered. The
//! streams are glibc's `FILE *` variables, which its headers declare.

use core::ffi::{CStr, VaList, c_char, c_int, c_void};

use super::{FILE, set_errno, size_t};
use crate::sys;

const fn stream(fd: c_int) -> FILE {
    FILE { fd, pos: 0, len: 0, buf: [0; 4096], line: [0; 4096] }
}

static mut STDIN: FILE = stream(0);
static mut STDOUT: FILE = stream(1);
static mut STDERR: FILE = stream(2);

#[unsafe(no_mangle)]
pub static mut stdin: *mut FILE = &raw mut STDIN;
#[unsafe(no_mangle)]
pub static mut stdout: *mut FILE = &raw mut STDOUT;
#[unsafe(no_mangle)]
pub static mut stderr: *mut FILE = &raw mut STDERR;

/// Whether `f` is one of the standard streams, which are not mapped.
pub(super) fn is_standard(f: *mut FILE) -> bool {
    [&raw mut STDIN, &raw mut STDOUT, &raw mut STDERR].contains(&f)
}

fn write_fd(fd: c_int, b: &[u8]) -> bool {
    let mut b = b;
    while !b.is_empty() {
        match unsafe { sys::write(fd, b.as_ptr(), b.len()) } {
            Ok(n) => b = &b[n..],
            Err(sys::EINTR) => {}
            Err(e) => {
                set_errno(e);
                return false;
            }
        }
    }
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fwrite(p: *const c_void, size: size_t, n: size_t, f: *mut FILE) -> size_t {
    let Some(len) = size.checked_mul(n) else { return 0 };
    let b = unsafe { core::slice::from_raw_parts(p.cast::<u8>(), len) };
    if write_fd(unsafe { (*f).fd }, b) { n } else { 0 }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fputs(s: *const c_char, f: *mut FILE) -> c_int {
    let b = unsafe { CStr::from_ptr(s) }.to_bytes();
    if write_fd(unsafe { (*f).fd }, b) { 0 } else { -1 }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn puts(s: *const c_char) -> c_int {
    unsafe { if fputs(s, stdout) < 0 || fputc(b'\n' as c_int, stdout) < 0 { -1 } else { 0 } }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fputc(c: c_int, f: *mut FILE) -> c_int {
    if write_fd(unsafe { (*f).fd }, &[c as u8]) { c as u8 as c_int } else { -1 }
}

/// Nothing is buffered.
#[unsafe(no_mangle)]
pub extern "C" fn fflush(_f: *mut FILE) -> c_int {
    0
}

// ---- printf ----

/// Where formatted output goes: it counts everything, and keeps what fits.
trait Sink {
    fn put(&mut self, b: &[u8]);
    fn count(&self) -> usize;
}

/// Into a buffer of `cap` bytes, NUL-terminated at the end.
struct Buffer {
    p: *mut u8,
    cap: usize,
    n: usize,
}

impl Sink for Buffer {
    fn put(&mut self, b: &[u8]) {
        // one byte kept for the NUL
        let room = self.cap.saturating_sub(1).saturating_sub(self.n);
        let k = b.len().min(room);
        unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), self.p.add(self.n.min(self.cap)), k) };
        self.n += b.len();
    }
    fn count(&self) -> usize {
        self.n
    }
}

/// To a file descriptor, through a small buffer.
struct Fd {
    fd: c_int,
    buf: [u8; 512],
    len: usize,
    n: usize,
    failed: bool,
}

impl Fd {
    fn flush(&mut self) {
        if self.len > 0 && !write_fd(self.fd, &self.buf[..self.len]) {
            self.failed = true;
        }
        self.len = 0;
    }
}

impl Sink for Fd {
    fn put(&mut self, b: &[u8]) {
        self.n += b.len();
        if self.len + b.len() > self.buf.len() {
            self.flush();
        }
        if b.len() > self.buf.len() {
            self.failed |= !write_fd(self.fd, b);
        } else {
            self.buf[self.len..self.len + b.len()].copy_from_slice(b);
            self.len += b.len();
        }
    }
    fn count(&self) -> usize {
        self.n
    }
}

/// A small text buffer for `core::fmt`, for floating-point conversions.
struct Text {
    b: [u8; 400],
    n: usize,
}

impl core::fmt::Write for Text {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let k = s.len().min(self.b.len() - self.n);
        self.b[self.n..self.n + k].copy_from_slice(&s.as_bytes()[..k]);
        self.n += k;
        Ok(())
    }
}

impl Text {
    fn new() -> Text {
        Text { b: [0; 400], n: 0 }
    }
    fn as_bytes(&self) -> &[u8] {
        &self.b[..self.n]
    }
}

#[derive(Default, Clone, Copy)]
struct Spec {
    left: bool,
    plus: bool,
    space: bool,
    alt: bool,
    zero: bool,
    width: usize,
    prec: Option<usize>,
}

/// Write `body` with its sign or prefix, padded to the field's width.
/// `zeros` is how many zeros go between the prefix and body for precision.
fn field(out: &mut dyn Sink, s: &Spec, prefix: &[u8], zeros: usize, body: &[u8], zero_pad: bool) {
    let len = prefix.len() + zeros + body.len();
    let pad = s.width.saturating_sub(len);
    let fill = |out: &mut dyn Sink, c: u8, n: usize| {
        for _ in 0..n {
            out.put(&[c]);
        }
    };
    if !s.left && !(zero_pad && s.zero) {
        fill(out, b' ', pad);
    }
    out.put(prefix);
    if !s.left && zero_pad && s.zero {
        fill(out, b'0', pad);
    }
    fill(out, b'0', zeros);
    out.put(body);
    if s.left {
        fill(out, b' ', pad);
    }
}

fn integer(out: &mut dyn Sink, s: &Spec, v: u64, neg: bool, conv: u8) {
    let base = match conv {
        b'o' => 8,
        b'x' | b'X' | b'p' => 16,
        _ => 10,
    };
    let digits: &[u8; 16] = if conv == b'X' { b"0123456789ABCDEF" } else { b"0123456789abcdef" };
    let mut buf = [0u8; 24];
    let mut i = buf.len();
    let mut x = v;
    while x > 0 {
        i -= 1;
        buf[i] = digits[(x % base) as usize];
        x /= base;
    }
    let body = &buf[i..];
    let prec = s.prec.unwrap_or(1);
    let mut zeros = prec.saturating_sub(body.len());
    let prefix: &[u8] = match conv {
        b'd' | b'i' if neg => b"-",
        b'd' | b'i' if s.plus => b"+",
        b'd' | b'i' if s.space => b" ",
        b'x' if s.alt && v != 0 => b"0x",
        b'X' if s.alt && v != 0 => b"0X",
        b'p' => b"0x",
        _ => b"",
    };
    if conv == b'o' && s.alt && zeros == 0 && body.first() != Some(&b'0') {
        zeros = 1;
    }
    // an explicit precision turns off zero padding
    field(out, s, prefix, zeros, body, s.prec.is_none());
}

fn float(out: &mut dyn Sink, s: &Spec, v: f64, conv: u8) {
    use core::fmt::Write;
    let upper = conv.is_ascii_uppercase();
    let sign: &[u8] = if v.is_sign_negative() { b"-" } else if s.plus { b"+" } else if s.space { b" " } else { b"" };
    if !v.is_finite() {
        let body: &[u8] = match (v.is_nan(), upper) {
            (true, false) => b"nan",
            (true, true) => b"NAN",
            (false, false) => b"inf",
            (false, true) => b"INF",
        };
        return field(out, s, sign, 0, body, false);
    }
    let v = v.abs();
    let prec = s.prec.unwrap_or(6).min(100);
    let mut t = Text::new();
    // Rust writes 1.5e3; C wants 1.5e+03
    let exp_form = |t: &mut Text, prec: usize| {
        let mut r = Text::new();
        let _ = write!(r, "{:.*e}", prec, v);
        let b = r.as_bytes();
        let e = b.iter().position(|&c| c == b'e').unwrap();
        let _ = t.write_str(core::str::from_utf8(&b[..e]).unwrap());
        let exp: i32 = core::str::from_utf8(&b[e + 1..]).unwrap().parse().unwrap();
        let _ = write!(t, "{}{}{:02}", if upper { 'E' } else { 'e' }, if exp < 0 { '-' } else { '+' }, exp.abs());
        exp
    };
    match conv.to_ascii_lowercase() {
        b'f' => {
            let _ = write!(t, "{:.*}", prec, v);
            if s.alt && prec == 0 {
                let _ = t.write_str(".");
            }
        }
        b'e' => {
            exp_form(&mut t, prec);
        }
        _ => {
            // %g: %e's exponent picks the form, then trailing zeros go
            let p = prec.max(1);
            let mut probe = Text::new();
            let x = exp_form(&mut probe, p - 1);
            if (-4..p as i32).contains(&x) {
                let _ = write!(t, "{:.*}", (p as i32 - 1 - x) as usize, v);
            } else {
                exp_form(&mut t, p - 1);
            }
            if !s.alt {
                let b = t.as_bytes();
                let e = b.iter().position(|&c| c == b'e' || c == b'E').unwrap_or(b.len());
                if b[..e].contains(&b'.') {
                    let mut end = e;
                    while b[end - 1] == b'0' {
                        end -= 1;
                    }
                    if b[end - 1] == b'.' {
                        end -= 1;
                    }
                    let mut g = Text::new();
                    g.b[..end].copy_from_slice(&b[..end]);
                    g.b[end..end + (b.len() - e)].copy_from_slice(&b[e..]);
                    g.n = end + (b.len() - e);
                    t = g;
                }
            }
        }
    }
    field(out, s, sign, 0, t.as_bytes(), true);
}

/// Format `fmt` with `ap` into `out`.
unsafe fn format(out: &mut dyn Sink, fmt: *const c_char, mut ap: VaList) {
    let fmt = unsafe { CStr::from_ptr(fmt) }.to_bytes();
    let mut i = 0;
    while i < fmt.len() {
        let start = i;
        while i < fmt.len() && fmt[i] != b'%' {
            i += 1;
        }
        out.put(&fmt[start..i]);
        if i >= fmt.len() {
            break;
        }
        let pct = i;
        i += 1;
        let at = |i: usize| fmt.get(i).copied().unwrap_or(0);
        let mut s = Spec::default();
        loop {
            match at(i) {
                b'-' => s.left = true,
                b'+' => s.plus = true,
                b' ' => s.space = true,
                b'#' => s.alt = true,
                b'0' => s.zero = true,
                _ => break,
            }
            i += 1;
        }
        if at(i) == b'*' {
            let w: c_int = unsafe { ap.next_arg() };
            s.left |= w < 0;
            s.width = w.unsigned_abs() as usize;
            i += 1;
        } else {
            while at(i).is_ascii_digit() {
                s.width = s.width * 10 + (at(i) - b'0') as usize;
                i += 1;
            }
        }
        if at(i) == b'.' {
            i += 1;
            if at(i) == b'*' {
                let p: c_int = unsafe { ap.next_arg() };
                s.prec = (p >= 0).then_some(p as usize);
                i += 1;
            } else {
                let mut p = 0;
                while at(i).is_ascii_digit() {
                    p = p * 10 + (at(i) - b'0') as usize;
                    i += 1;
                }
                s.prec = Some(p);
            }
        }
        // length: 0 = int, 1 = char, 2 = short, 8 = 64-bit
        let mut len = 0;
        loop {
            match at(i) {
                b'h' => len = if len == 2 { 1 } else { 2 },
                b'l' | b'z' | b'j' | b't' | b'q' | b'L' => len = 8,
                _ => break,
            }
            i += 1;
        }
        let conv = at(i);
        i += 1;
        match conv {
            b'd' | b'i' => {
                let v: i64 = match len {
                    8 => unsafe { ap.next_arg::<i64>() },
                    1 => (unsafe { ap.next_arg::<c_int>() }) as i8 as i64,
                    2 => (unsafe { ap.next_arg::<c_int>() }) as i16 as i64,
                    _ => (unsafe { ap.next_arg::<c_int>() }) as i64,
                };
                integer(out, &s, v.unsigned_abs(), v < 0, conv);
            }
            b'u' | b'o' | b'x' | b'X' => {
                let v: u64 = match len {
                    8 => unsafe { ap.next_arg::<u64>() },
                    1 => (unsafe { ap.next_arg::<u32>() }) as u8 as u64,
                    2 => (unsafe { ap.next_arg::<u32>() }) as u16 as u64,
                    _ => (unsafe { ap.next_arg::<u32>() }) as u64,
                };
                integer(out, &s, v, false, conv);
            }
            b'p' => {
                let p = unsafe { ap.next_arg::<*const c_void>() } as u64;
                if p == 0 {
                    field(out, &s, b"", 0, b"(nil)", false);
                } else {
                    integer(out, &Spec { prec: None, ..s }, p, false, b'p');
                }
            }
            b'c' => {
                let c = unsafe { ap.next_arg::<c_int>() } as u8;
                field(out, &s, b"", 0, &[c], false);
            }
            b's' => {
                let p = unsafe { ap.next_arg::<*const c_char>() };
                let b: &[u8] = if p.is_null() {
                    b"(null)"
                } else {
                    let n = unsafe { super::string::strnlen(p, s.prec.unwrap_or(usize::MAX)) };
                    unsafe { core::slice::from_raw_parts(p.cast(), n) }
                };
                field(out, &s, b"", 0, b, false);
            }
            b'f' | b'F' | b'e' | b'E' | b'g' | b'G' => {
                let v = unsafe { ap.next_arg::<f64>() };
                float(out, &s, v, conv);
            }
            b'n' => {
                let p = unsafe { ap.next_arg::<*mut c_int>() };
                unsafe { *p = out.count() as c_int };
            }
            b'%' => out.put(b"%"),
            // an unknown conversion: printed as it is
            _ => out.put(&fmt[pct..i.min(fmt.len())]),
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vsnprintf(buf: *mut c_char, n: size_t, fmt: *const c_char, ap: VaList) -> c_int {
    let mut out = Buffer { p: buf.cast(), cap: n, n: 0 };
    unsafe { format(&mut out, fmt, ap) };
    if n > 0 {
        unsafe { *buf.add(out.n.min(n - 1)) = 0 };
    }
    out.n as c_int
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn snprintf(buf: *mut c_char, n: size_t, fmt: *const c_char, ap: ...) -> c_int {
    unsafe { vsnprintf(buf, n, fmt, ap) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vsprintf(buf: *mut c_char, fmt: *const c_char, ap: VaList) -> c_int {
    unsafe { vsnprintf(buf, usize::MAX, fmt, ap) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sprintf(buf: *mut c_char, fmt: *const c_char, ap: ...) -> c_int {
    unsafe { vsnprintf(buf, usize::MAX, fmt, ap) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vfprintf(f: *mut FILE, fmt: *const c_char, ap: VaList) -> c_int {
    let mut out = Fd { fd: unsafe { (*f).fd }, buf: [0; 512], len: 0, n: 0, failed: false };
    unsafe { format(&mut out, fmt, ap) };
    out.flush();
    if out.failed { -1 } else { out.n as c_int }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fprintf(f: *mut FILE, fmt: *const c_char, ap: ...) -> c_int {
    unsafe { vfprintf(f, fmt, ap) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn printf(fmt: *const c_char, ap: ...) -> c_int {
    unsafe { vfprintf(stdout, fmt, ap) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn perror(s: *const c_char) {
    let e = unsafe { *crate::errno::location() };
    let mut out = Fd { fd: 2, buf: [0; 512], len: 0, n: 0, failed: false };
    if !s.is_null() && unsafe { *s } != 0 {
        out.put(unsafe { CStr::from_ptr(s) }.to_bytes());
        out.put(b": ");
    }
    out.put(sys::strerror(e).as_bytes());
    out.put(b"\n");
    out.flush();
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __assert_fail(expr: *const c_char, file: *const c_char, line: u32, func: *const c_char) -> ! {
    let mut out = Fd { fd: 2, buf: [0; 512], len: 0, n: 0, failed: false };
    let mut num = Text::new();
    let _ = core::fmt::Write::write_fmt(&mut num, format_args!(":{line}: "));
    for part in [unsafe { CStr::from_ptr(file) }.to_bytes(), num.as_bytes(), unsafe { CStr::from_ptr(func) }.to_bytes()] {
        out.put(part);
    }
    out.put(b": Assertion `");
    out.put(unsafe { CStr::from_ptr(expr) }.to_bytes());
    out.put(b"' failed.\n");
    out.flush();
    crate::start::abort()
}

// ---- scanf ----

/// `sscanf`'s integer, string and character conversions (no floats, no
/// scansets): the number of conversions stored, or -1 if the input ended
/// before the first.
unsafe fn scan(input: *const c_char, fmt: *const c_char, mut ap: VaList) -> c_int {
    let s = unsafe { CStr::from_ptr(input) }.to_bytes();
    let fmt = unsafe { CStr::from_ptr(fmt) }.to_bytes();
    let (mut i, mut f, mut stored) = (0, 0, 0);
    let space = |c: u8| matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r');
    while f < fmt.len() {
        let c = fmt[f];
        if space(c) {
            while i < s.len() && space(s[i]) {
                i += 1;
            }
            f += 1;
            continue;
        }
        if c != b'%' || fmt.get(f + 1) == Some(&b'%') {
            let c = if c == b'%' { f += 1; b'%' } else { c };
            if s.get(i) != Some(&c) {
                break;
            }
            i += 1;
            f += 1;
            continue;
        }
        f += 1;
        let skip = fmt.get(f) == Some(&b'*');
        if skip {
            f += 1;
        }
        let mut width = 0;
        while let Some(d) = fmt.get(f).filter(|d| d.is_ascii_digit()) {
            width = width * 10 + (d - b'0') as usize;
            f += 1;
        }
        // 0 = int, 1 = char, 2 = short, 8 = 64-bit
        let mut len = 0;
        while let Some(&m) = fmt.get(f) {
            match m {
                b'h' => len = if len == 2 { 1 } else { 2 },
                b'l' | b'z' | b'j' | b't' | b'q' | b'L' => len = 8,
                _ => break,
            }
            f += 1;
        }
        let Some(&conv) = fmt.get(f) else { break };
        f += 1;
        if conv != b'c' && conv != b'n' {
            while i < s.len() && space(s[i]) {
                i += 1;
            }
        }
        if i >= s.len() && conv != b'n' {
            return if stored == 0 { -1 } else { stored };
        }
        let max = if width == 0 { usize::MAX } else { width };
        match conv {
            b'd' | b'i' | b'u' | b'x' | b'X' | b'o' => {
                let base = match conv {
                    b'x' | b'X' => 16,
                    b'o' => 8,
                    b'i' => 0,
                    _ => 10,
                };
                // the field, cut to its width, parsed as strtoull does
                let mut field = [0u8; 72];
                let n = (s.len() - i).min(max).min(field.len() - 1);
                field[..n].copy_from_slice(&s[i..i + n]);
                let mut end = core::ptr::null_mut();
                let v = unsafe { super::string::strtoull(field.as_ptr().cast(), &mut end, base) };
                let used = end as usize - field.as_ptr() as usize;
                if used == 0 {
                    break;
                }
                i += used;
                if !skip {
                    unsafe {
                        match len {
                            8 => *ap.next_arg::<*mut u64>() = v,
                            1 => *ap.next_arg::<*mut u8>() = v as u8,
                            2 => *ap.next_arg::<*mut u16>() = v as u16,
                            _ => *ap.next_arg::<*mut u32>() = v as u32,
                        }
                    }
                    stored += 1;
                }
            }
            b's' => {
                let start = i;
                while i < s.len() && !space(s[i]) && i - start < max {
                    i += 1;
                }
                if !skip {
                    let p = unsafe { ap.next_arg::<*mut u8>() };
                    unsafe {
                        core::ptr::copy_nonoverlapping(s[start..i].as_ptr(), p, i - start);
                        *p.add(i - start) = 0;
                    }
                    stored += 1;
                }
            }
            b'c' => {
                let n = if width == 0 { 1 } else { width };
                if s.len() - i < n {
                    break;
                }
                if !skip {
                    let p = unsafe { ap.next_arg::<*mut u8>() };
                    unsafe { core::ptr::copy_nonoverlapping(s[i..].as_ptr(), p, n) };
                    stored += 1;
                }
                i += n;
            }
            b'n' => {
                if !skip {
                    unsafe { *ap.next_arg::<*mut c_int>() = i as c_int };
                }
            }
            _ => break,
        }
    }
    stored
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vsscanf(s: *const c_char, fmt: *const c_char, ap: VaList) -> c_int {
    unsafe { scan(s, fmt, ap) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sscanf(s: *const c_char, fmt: *const c_char, ap: ...) -> c_int {
    unsafe { scan(s, fmt, ap) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __isoc23_sscanf(s: *const c_char, fmt: *const c_char, ap: ...) -> c_int {
    unsafe { scan(s, fmt, ap) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __isoc99_sscanf(s: *const c_char, fmt: *const c_char, ap: ...) -> c_int {
    unsafe { scan(s, fmt, ap) }
}
