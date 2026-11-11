//! `<string.h>`, `<ctype.h>` and `strtol`, for C code in crates.
//!
//! C code is compiled against the host's headers, which are glibc's: its
//! ctype macros index the tables `__ctype_b_loc` and friends return, and
//! C23 compilers call `strtol` as `__isoc23_strtol`. Only the C locale.

use core::ffi::{CStr, c_char, c_int, c_long, c_longlong, c_ulong, c_ulonglong, c_void};

use super::{set_errno, size_t};
use crate::sys;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memchr(s: *const c_void, c: c_int, n: size_t) -> *mut c_void {
    let s = unsafe { core::slice::from_raw_parts(s.cast::<u8>(), n) };
    match s.iter().position(|&b| b == c as u8) {
        Some(i) => s[i..].as_ptr().cast_mut().cast(),
        None => core::ptr::null_mut(),
    }
}

unsafe fn bytes<'a>(s: *const c_char) -> &'a [u8] {
    unsafe { CStr::from_ptr(s) }.to_bytes()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strnlen(s: *const c_char, max: size_t) -> size_t {
    let mut n = 0;
    while n < max && unsafe { *s.add(n) } != 0 {
        n += 1;
    }
    n
}

/// `strchr`: the terminating NUL is found too.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strchr(s: *const c_char, c: c_int) -> *mut c_char {
    let b = unsafe { CStr::from_ptr(s) }.to_bytes_with_nul();
    match b.iter().position(|&x| x == c as u8) {
        Some(i) => unsafe { s.add(i).cast_mut() },
        None => core::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strrchr(s: *const c_char, c: c_int) -> *mut c_char {
    let b = unsafe { CStr::from_ptr(s) }.to_bytes_with_nul();
    match b.iter().rposition(|&x| x == c as u8) {
        Some(i) => unsafe { s.add(i).cast_mut() },
        None => core::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strstr(hay: *const c_char, needle: *const c_char) -> *mut c_char {
    let (h, n) = unsafe { (bytes(hay), bytes(needle)) };
    if n.is_empty() {
        return hay.cast_mut();
    }
    match h.windows(n.len()).position(|w| w == n) {
        Some(i) => unsafe { hay.add(i).cast_mut() },
        None => core::ptr::null_mut(),
    }
}

/// Compare at most `n` bytes, mapping each through `f`.
unsafe fn compare(a: *const c_char, b: *const c_char, n: size_t, f: fn(u8) -> u8) -> c_int {
    for i in 0..n {
        let (x, y) = unsafe { (f(*a.add(i) as u8), f(*b.add(i) as u8)) };
        if x != y || x == 0 {
            return x as c_int - y as c_int;
        }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcmp(a: *const c_char, b: *const c_char) -> c_int {
    unsafe { compare(a, b, usize::MAX, |c| c) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strncmp(a: *const c_char, b: *const c_char, n: size_t) -> c_int {
    unsafe { compare(a, b, n, |c| c) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcasecmp(a: *const c_char, b: *const c_char) -> c_int {
    unsafe { compare(a, b, usize::MAX, |c| c.to_ascii_lowercase()) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strncasecmp(a: *const c_char, b: *const c_char, n: size_t) -> c_int {
    unsafe { compare(a, b, n, |c| c.to_ascii_lowercase()) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcpy(dst: *mut c_char, src: *const c_char) -> *mut c_char {
    let s = unsafe { CStr::from_ptr(src) }.to_bytes_with_nul();
    unsafe { core::ptr::copy_nonoverlapping(s.as_ptr(), dst.cast(), s.len()) };
    dst
}

/// `strncpy`: NUL-padded to `n`, and not terminated if `src` is longer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strncpy(dst: *mut c_char, src: *const c_char, n: size_t) -> *mut c_char {
    let len = unsafe { strnlen(src, n) };
    unsafe {
        core::ptr::copy_nonoverlapping(src, dst, len);
        dst.add(len).write_bytes(0, n - len);
    }
    dst
}

/// A message for a C caller to keep: the thread's buffer, until its next call.
#[thread_local]
static mut MESSAGE: [u8; 64] = [0; 64];

fn message(parts: &[&[u8]]) -> *mut c_char {
    let buf = unsafe { &mut *&raw mut MESSAGE };
    let mut n = 0;
    for p in parts {
        let take = p.len().min(buf.len() - 1 - n);
        buf[n..n + take].copy_from_slice(&p[..take]);
        n += take;
    }
    buf[n] = 0;
    buf.as_mut_ptr().cast()
}

#[unsafe(no_mangle)]
pub extern "C" fn strerror(e: c_int) -> *mut c_char {
    message(&[sys::strerror(e).as_bytes()])
}

#[unsafe(no_mangle)]
pub extern "C" fn strsignal(sig: c_int) -> *mut c_char {
    let name: &[u8] = match sig {
        1 => b"Hangup",
        2 => b"Interrupt",
        3 => b"Quit",
        4 => b"Illegal instruction",
        5 => b"Trace/breakpoint trap",
        6 => b"Aborted",
        7 => b"Bus error",
        8 => b"Floating point exception",
        9 => b"Killed",
        10 => b"User defined signal 1",
        11 => b"Segmentation fault",
        12 => b"User defined signal 2",
        13 => b"Broken pipe",
        14 => b"Alarm clock",
        15 => b"Terminated",
        17 => b"Child exited",
        18 => b"Continued",
        19 => b"Stopped (signal)",
        20 => b"Stopped",
        28 => b"Window changed",
        _ => b"Unknown signal",
    };
    message(&[name])
}

// ---- ctype, as glibc's tables ----

// glibc's class bits, as its little-endian `_ISbit` lays them out
const UPPER: u16 = 1 << 8;
const LOWER: u16 = 1 << 9;
const ALPHA: u16 = 1 << 10;
const DIGIT: u16 = 1 << 11;
const XDIGIT: u16 = 1 << 12;
const SPACE: u16 = 1 << 13;
const PRINT: u16 = 1 << 14;
const GRAPH: u16 = 1 << 15;
const BLANK: u16 = 1 << 0;
const CNTRL: u16 = 1 << 1;
const PUNCT: u16 = 1 << 2;
const ALNUM: u16 = 1 << 3;

const fn class(c: u8) -> u16 {
    let mut m = 0;
    if c.is_ascii_uppercase() {
        m |= UPPER | ALPHA | ALNUM;
    }
    if c.is_ascii_lowercase() {
        m |= LOWER | ALPHA | ALNUM;
    }
    if c.is_ascii_digit() {
        m |= DIGIT | ALNUM;
    }
    if c.is_ascii_hexdigit() {
        m |= XDIGIT;
    }
    if matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        m |= SPACE;
    }
    if matches!(c, b' ' | b'\t') {
        m |= BLANK;
    }
    if c.is_ascii_control() {
        m |= CNTRL;
    }
    if c.is_ascii_graphic() {
        m |= GRAPH | PRINT;
    }
    if c == b' ' {
        m |= PRINT;
    }
    if c.is_ascii_punctuation() {
        m |= PUNCT;
    }
    m
}

/// Indexed from -128 (signed chars) to 255; the pointers point at 0.
static CLASSES: [u16; 384] = {
    let mut t = [0; 384];
    let mut i = 0;
    while i < 128 {
        t[128 + i] = class(i as u8);
        i += 1;
    }
    t
};

static LOWERED: [i32; 384] = case_table(false);
static UPPERED: [i32; 384] = case_table(true);

const fn case_table(upper: bool) -> [i32; 384] {
    let mut t = [0; 384];
    let mut i = 0;
    while i < 384 {
        let c = i as i32 - 128;
        t[i] = if c >= 0 && c < 128 {
            let b = c as u8;
            (if upper { b.to_ascii_uppercase() } else { b.to_ascii_lowercase() }) as i32
        } else {
            c
        };
        i += 1;
    }
    t
}

struct Table<T: 'static>(*const T);
unsafe impl<T> Sync for Table<T> {}

static CLASSES_AT: Table<u16> = Table(CLASSES.as_ptr().wrapping_add(128));
static LOWERED_AT: Table<i32> = Table(LOWERED.as_ptr().wrapping_add(128));
static UPPERED_AT: Table<i32> = Table(UPPERED.as_ptr().wrapping_add(128));

#[unsafe(no_mangle)]
pub extern "C" fn __ctype_b_loc() -> *const *const u16 {
    &raw const CLASSES_AT.0
}

#[unsafe(no_mangle)]
pub extern "C" fn __ctype_tolower_loc() -> *const *const i32 {
    &raw const LOWERED_AT.0
}

#[unsafe(no_mangle)]
pub extern "C" fn __ctype_toupper_loc() -> *const *const i32 {
    &raw const UPPERED_AT.0
}

fn is(c: c_int, m: u16) -> c_int {
    ((-128..256).contains(&c) && CLASSES[(c + 128) as usize] & m != 0) as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn isalpha(c: c_int) -> c_int {
    is(c, ALPHA)
}
#[unsafe(no_mangle)]
pub extern "C" fn isdigit(c: c_int) -> c_int {
    is(c, DIGIT)
}
#[unsafe(no_mangle)]
pub extern "C" fn isalnum(c: c_int) -> c_int {
    is(c, ALNUM)
}
#[unsafe(no_mangle)]
pub extern "C" fn isspace(c: c_int) -> c_int {
    is(c, SPACE)
}
#[unsafe(no_mangle)]
pub extern "C" fn isupper(c: c_int) -> c_int {
    is(c, UPPER)
}
#[unsafe(no_mangle)]
pub extern "C" fn islower(c: c_int) -> c_int {
    is(c, LOWER)
}
#[unsafe(no_mangle)]
pub extern "C" fn isxdigit(c: c_int) -> c_int {
    is(c, XDIGIT)
}
#[unsafe(no_mangle)]
pub extern "C" fn isprint(c: c_int) -> c_int {
    is(c, PRINT)
}
#[unsafe(no_mangle)]
pub extern "C" fn tolower(c: c_int) -> c_int {
    if (-128..256).contains(&c) { LOWERED[(c + 128) as usize] } else { c }
}
#[unsafe(no_mangle)]
pub extern "C" fn toupper(c: c_int) -> c_int {
    if (-128..256).contains(&c) { UPPERED[(c + 128) as usize] } else { c }
}

// ---- strtol ----

/// Parse an integer as `strtoull` does: its magnitude (saturated, with
/// `overflow` set), its sign, and where it ended (`s` if there is none).
unsafe fn parse(s: *const c_char, end: *mut *mut c_char, base: c_int) -> (u64, bool, bool) {
    let mut p = s as *const u8;
    let at = |p: *const u8| unsafe { *p };
    while matches!(at(p), b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        p = unsafe { p.add(1) };
    }
    let neg = at(p) == b'-';
    if matches!(at(p), b'+' | b'-') {
        p = unsafe { p.add(1) };
    }
    let mut base = base as u32;
    let hex_prefix = at(p) == b'0' && matches!(at(unsafe { p.add(1) }), b'x' | b'X') && unsafe { (*p.add(2) as char).is_ascii_hexdigit() };
    if (base == 0 || base == 16) && hex_prefix {
        p = unsafe { p.add(2) };
        base = 16;
    } else if base == 0 {
        base = if at(p) == b'0' { 8 } else { 10 };
    }
    if !(2..=36).contains(&base) {
        set_errno(sys::EINVAL);
        if !end.is_null() {
            unsafe { *end = s.cast_mut() };
        }
        return (0, false, false);
    }
    let (mut v, mut over, mut any) = (0u64, false, false);
    while let Some(d) = (at(p) as char).to_digit(base) {
        any = true;
        match v.checked_mul(base as u64).and_then(|v| v.checked_add(d as u64)) {
            Some(n) => v = n,
            None => over = true,
        }
        p = unsafe { p.add(1) };
    }
    if !end.is_null() {
        unsafe { *end = if any { p as *mut c_char } else { s.cast_mut() } };
    }
    (if over { u64::MAX } else { v }, neg, over)
}

unsafe fn signed(s: *const c_char, end: *mut *mut c_char, base: c_int) -> i64 {
    let (v, neg, over) = unsafe { parse(s, end, base) };
    let limit = if neg { i64::MIN.unsigned_abs() } else { i64::MAX as u64 };
    if over || v > limit {
        set_errno(sys::ERANGE);
        return if neg { i64::MIN } else { i64::MAX };
    }
    if neg { (v as i64).wrapping_neg() } else { v as i64 }
}

unsafe fn unsigned(s: *const c_char, end: *mut *mut c_char, base: c_int) -> u64 {
    let (v, neg, over) = unsafe { parse(s, end, base) };
    if over {
        set_errno(sys::ERANGE);
        return u64::MAX;
    }
    if neg { v.wrapping_neg() } else { v }
}

// c_long is 64-bit on both targets, so every width is the same function
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strtol(s: *const c_char, end: *mut *mut c_char, base: c_int) -> c_long {
    unsafe { signed(s, end, base) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strtoll(s: *const c_char, end: *mut *mut c_char, base: c_int) -> c_longlong {
    unsafe { signed(s, end, base) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strtoul(s: *const c_char, end: *mut *mut c_char, base: c_int) -> c_ulong {
    unsafe { unsigned(s, end, base) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strtoull(s: *const c_char, end: *mut *mut c_char, base: c_int) -> c_ulonglong {
    unsafe { unsigned(s, end, base) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __isoc23_strtol(s: *const c_char, end: *mut *mut c_char, base: c_int) -> c_long {
    unsafe { signed(s, end, base) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __isoc23_strtoll(s: *const c_char, end: *mut *mut c_char, base: c_int) -> c_longlong {
    unsafe { signed(s, end, base) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __isoc23_strtoul(s: *const c_char, end: *mut *mut c_char, base: c_int) -> c_ulong {
    unsafe { unsigned(s, end, base) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __isoc23_strtoull(s: *const c_char, end: *mut *mut c_char, base: c_int) -> c_ulonglong {
    unsafe { unsigned(s, end, base) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn atoi(s: *const c_char) -> c_int {
    unsafe { signed(s, core::ptr::null_mut(), 10) as c_int }
}

/// libgcc's popcount, which gcc calls for `__builtin_popcountll` without
/// a popcnt instruction (mimalloc does).
#[unsafe(no_mangle)]
pub extern "C" fn __popcountdi2(x: i64) -> c_int {
    x.count_ones() as c_int
}
