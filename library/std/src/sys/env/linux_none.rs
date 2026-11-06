//! The environment on linux-none: std owns `environ`. It starts as the array
//! the kernel passed to the process; `setenv`/`unsetenv` replace it with a
//! fresh array under `ENV_LOCK`. Replaced strings are leaked, as libc does,
//! so that a `getenv` result copied out under the read lock stays valid.

use core::slice::memchr;

use libc::c_char;

pub use super::common::Env;
use crate::ffi::{CStr, CString, OsStr, OsString};
use crate::io;
use crate::os::unix::prelude::*;
use crate::ptr;
use crate::sync::{PoisonError, RwLock};

static ENV_LOCK: RwLock<()> = RwLock::new(());

/// The current `environ` array, once it has been modified (null before).
static mut ENVIRON: *const *const c_char = ptr::null();
/// The array `ENVIRON` points to, when std allocated it.
static mut OWNED: Vec<*const c_char> = Vec::new();

/// The null-terminated `KEY=VALUE` array, as libc's `environ`. Read it only
/// while holding [`env_read_lock`].
pub fn environ() -> *const *const c_char {
    unsafe {
        let e = ENVIRON;
        if e.is_null() { linux_none_rt::start::envp().cast() } else { e }
    }
}

pub fn env_read_lock() -> impl Drop {
    ENV_LOCK.read().unwrap_or_else(PoisonError::into_inner)
}

fn entries() -> impl Iterator<Item = &'static [u8]> {
    let mut p = environ();
    crate::iter::from_fn(move || unsafe {
        if p.is_null() || (*p).is_null() {
            return None;
        }
        let s = CStr::from_ptr(*p).to_bytes();
        p = p.add(1);
        Some(s)
    })
}

fn parse(input: &[u8]) -> Option<(&[u8], &[u8])> {
    // a leading `=` is part of the key (as on Windows' per-drive variables)
    if input.is_empty() {
        return None;
    }
    let pos = memchr::memchr(b'=', &input[1..]).map(|p| p + 1)?;
    Some((&input[..pos], &input[pos + 1..]))
}

pub fn env() -> Env {
    let _guard = env_read_lock();
    let result = entries()
        .filter_map(parse)
        .map(|(k, v)| (OsStringExt::from_vec(k.to_vec()), OsStringExt::from_vec(v.to_vec())))
        .collect();
    Env::new(result)
}

pub fn getenv(k: &OsStr) -> Option<OsString> {
    let k = k.as_bytes();
    let _guard = env_read_lock();
    entries().filter_map(parse).find(|(key, _)| *key == k).map(|(_, v)| OsStringExt::from_vec(v.to_vec()))
}

fn invalid_key(k: &[u8]) -> bool {
    k.is_empty() || k.contains(&b'=') || k.contains(&0)
}

/// Replace the variable `k` with `new` (`KEY=VALUE`), or remove it.
fn update(k: &[u8], new: Option<CString>) {
    let _guard = ENV_LOCK.write().unwrap_or_else(PoisonError::into_inner);
    let mut v: Vec<*const c_char> = Vec::new();
    let mut p = environ();
    unsafe {
        while !p.is_null() && !(*p).is_null() {
            let entry = CStr::from_ptr(*p).to_bytes();
            if !parse(entry).is_some_and(|(key, _)| key == k) {
                v.push(*p);
            }
            p = p.add(1);
        }
    }
    if let Some(new) = new {
        v.push(new.into_raw());
    }
    v.push(ptr::null());
    unsafe {
        ENVIRON = v.as_ptr();
        *&raw mut OWNED = v;
    }
}

pub unsafe fn setenv(k: &OsStr, v: &OsStr) -> io::Result<()> {
    let (k, v) = (k.as_bytes(), v.as_bytes());
    if invalid_key(k) || v.contains(&0) {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let mut kv = Vec::with_capacity(k.len() + v.len() + 1);
    kv.extend_from_slice(k);
    kv.push(b'=');
    kv.extend_from_slice(v);
    update(k, Some(CString::new(kv).unwrap()));
    Ok(())
}

pub unsafe fn unsetenv(k: &OsStr) -> io::Result<()> {
    let k = k.as_bytes();
    if invalid_key(k) {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    update(k, None);
    Ok(())
}
