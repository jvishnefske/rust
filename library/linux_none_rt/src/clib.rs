//! The C library functions that crates call through the `libc` crate, for
//! programs on linux-none, where there is no libc to provide them.
//!
//! The libc crate gives such crates musl's types and constants (see
//! `cargo xtask libc-fixup`); these are its functions, as musl defines them,
//! on the runtime's syscalls. They cover what common crates use (terminals,
//! mmap, CPU counts, epoll, signals, semaphores, users and groups, fork and
//! exec, malloc), not all of libc: C stdio is only enough to read
//! files line by line, and there is no locale.
//!
//! Variadic functions (`open`, `ioctl`, `syscall`) take their full argument
//! list: on x86_64 and aarch64 Linux, variadic integer arguments are passed
//! as fixed ones are, and the unused ones are never read meaningfully.
//!
//! The environment (`getenv`, `execv`, `execvp`) is the initial one, from
//! the process's stack: changes made through std's `env::set_var` are not
//! seen.

#![allow(non_camel_case_types)]

mod pthread;
mod stdio;
mod string;

use string::strcpy;

use core::ffi::{CStr, c_char, c_int, c_long, c_uint, c_ulong, c_void};
use core::sync::atomic::{AtomicU32, Ordering};

use crate::arch::{KSigaction, nr};
use crate::sys::{self, AT_FDCWD, SysResult};
use crate::{elf, errno, futex, start, tz};

type size_t = usize;
type ssize_t = isize;
type pid_t = i32;
type uid_t = u32;
type gid_t = u32;

fn set_errno(e: i32) {
    unsafe { *errno::location() = e };
}

/// The C convention: the value, or -1 with `errno` set.
fn ret(r: SysResult) -> isize {
    match r {
        Ok(v) => v as isize,
        Err(e) => {
            set_errno(e);
            -1
        }
    }
}

fn ret_int(r: SysResult) -> c_int {
    ret(r) as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn __errno_location() -> *mut c_int {
    errno::location()
}

// ---- file descriptors ----

#[unsafe(no_mangle)]
pub unsafe extern "C" fn read(fd: c_int, buf: *mut c_void, n: size_t) -> ssize_t {
    ret(unsafe { sys::read(fd, buf.cast(), n) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn write(fd: c_int, buf: *const c_void, n: size_t) -> ssize_t {
    ret(unsafe { sys::write(fd, buf.cast(), n) })
}

#[unsafe(no_mangle)]
pub extern "C" fn close(fd: c_int) -> c_int {
    ret_int(sys::close(fd))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn open(path: *const c_char, flags: c_int, mode: c_uint) -> c_int {
    unsafe { openat(AT_FDCWD, path, flags, mode) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn openat(dirfd: c_int, path: *const c_char, flags: c_int, mode: c_uint) -> c_int {
    ret_int(unsafe { sys::openat(dirfd, path.cast(), flags as u32, mode) }.map(|fd| fd as usize))
}

#[unsafe(no_mangle)]
pub extern "C" fn dup(fd: c_int) -> c_int {
    ret_int(sys::dup(fd).map(|fd| fd as usize))
}

#[unsafe(no_mangle)]
pub extern "C" fn dup2(old: c_int, new: c_int) -> c_int {
    if old == new {
        // dup3 rejects equal descriptors; dup2 checks `old` is open
        return ret_int(sys::fcntl(old, sys::F_GETFD, 0).map(|_| new as usize));
    }
    ret_int(sys::dup3(old, new, 0).map(|fd| fd as usize))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pipe(fds: *mut c_int) -> c_int {
    unsafe { pipe2(fds, 0) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pipe2(fds: *mut c_int, flags: c_int) -> c_int {
    match sys::pipe2(flags as u32) {
        Ok(p) => {
            unsafe { fds.cast::<[i32; 2]>().write(p) };
            0
        }
        Err(e) => ret_int(Err(e)),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn splice(
    fd_in: c_int,
    off_in: *mut i64,
    fd_out: c_int,
    off_out: *mut i64,
    len: size_t,
    flags: c_uint,
) -> ssize_t {
    let args = [fd_in as usize, off_in as usize, fd_out as usize, off_out as usize, len, flags as usize];
    ret(unsafe { sys::syscall(nr::SPLICE, args) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ioctl(fd: c_int, req: c_ulong, arg: usize) -> c_int {
    ret_int(unsafe { sys::ioctl(fd, req as usize, arg) })
}

const TCGETS: usize = 0x5401;

#[unsafe(no_mangle)]
pub extern "C" fn isatty(fd: c_int) -> c_int {
    // a `struct termios`, which the kernel fills for terminals only
    let mut termios = [0u8; 64];
    match unsafe { sys::ioctl(fd, TCGETS, termios.as_mut_ptr() as usize) } {
        Ok(_) => 1,
        Err(e) => {
            set_errno(e);
            0
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn access(path: *const c_char, mode: c_int) -> c_int {
    unsafe { faccessat(AT_FDCWD, path, mode, 0) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn faccessat(dirfd: c_int, path: *const c_char, mode: c_int, flags: c_int) -> c_int {
    ret_int(if flags == 0 {
        unsafe { sys::faccessat(dirfd, path.cast(), mode as u32) }
    } else {
        unsafe { sys::syscall(nr::FACCESSAT2, [dirfd as usize, path as usize, mode as usize, flags as usize, 0, 0]) }
    })
}

/// `syscall(n, ...)`: the raw syscall, with the C convention for errors.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn syscall(n: c_long, a: c_long, b: c_long, c: c_long, d: c_long, e: c_long, f: c_long) -> c_long {
    let args = [a, b, c, d, e, f].map(|x| x as usize);
    ret(unsafe { sys::syscall(n as usize, args) }) as c_long
}

#[unsafe(no_mangle)]
pub extern "C" fn _exit(code: c_int) -> ! {
    sys::exit_group(code)
}

// ---- identity ----

#[unsafe(no_mangle)]
pub extern "C" fn getpid() -> pid_t {
    sys::getpid() as pid_t
}

#[unsafe(no_mangle)]
pub extern "C" fn getppid() -> pid_t {
    sys::getppid() as pid_t
}

#[unsafe(no_mangle)]
pub extern "C" fn getuid() -> uid_t {
    sys::getuid()
}

#[unsafe(no_mangle)]
pub extern "C" fn geteuid() -> uid_t {
    sys::geteuid()
}

#[unsafe(no_mangle)]
pub extern "C" fn getgid() -> gid_t {
    sys::getgid()
}

#[unsafe(no_mangle)]
pub extern "C" fn getegid() -> gid_t {
    sys::getegid()
}

/// `struct utsname`: six 65-byte fields, as the kernel's `new_utsname`.
const UTS_LEN: usize = 65;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn uname(buf: *mut c_void) -> c_int {
    ret_int(unsafe { sys::uname(buf.cast()) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn gethostname(name: *mut c_char, len: size_t) -> c_int {
    let mut uts = [0u8; 6 * UTS_LEN];
    if let Err(e) = unsafe { sys::uname(uts.as_mut_ptr()) } {
        return ret_int(Err(e));
    }
    let node = &uts[UTS_LEN..2 * UTS_LEN];
    let n = node.iter().position(|&b| b == 0).unwrap_or(UTS_LEN - 1);
    if n >= len {
        return ret_int(Err(sys::ENAMETOOLONG));
    }
    unsafe {
        core::ptr::copy_nonoverlapping(node.as_ptr(), name.cast(), n);
        *name.add(n) = 0;
    }
    0
}

/// The value in `entry` (`NAME=value`) if it is `name`'s.
unsafe fn env_value(entry: *const u8, name: &[u8]) -> Option<*mut c_char> {
    let e = unsafe { CStr::from_ptr(entry.cast()) }.to_bytes();
    (e.len() > name.len() && e.starts_with(name) && e[name.len()] == b'=').then(|| unsafe { entry.add(name.len() + 1) } as *mut c_char)
}

/// The entries `putenv` added, which `getenv` consults before the initial
/// environment (latest first).
struct PutEnv {
    lock: crate::locks::RawMutex,
    entries: core::cell::UnsafeCell<([usize; 64], usize)>,
}

// SAFETY: `entries` is only used with `lock` held
unsafe impl Sync for PutEnv {}

impl PutEnv {
    fn with<R>(&self, f: impl FnOnce(&mut [usize; 64], &mut usize) -> R) -> R {
        self.lock.lock();
        let (entries, n) = unsafe { &mut *self.entries.get() };
        let r = f(entries, n);
        unsafe { self.lock.unlock() };
        r
    }
}

static PUTENV: PutEnv = PutEnv { lock: crate::locks::RawMutex::new(), entries: core::cell::UnsafeCell::new(([0; 64], 0)) };

/// `putenv`: `string` (`NAME=value`, kept, not copied) is seen by later
/// `getenv` calls, not by std's `env::var` or child processes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn putenv(string: *mut c_char) -> c_int {
    let s = unsafe { CStr::from_ptr(string) }.to_bytes();
    let Some(eq) = s.iter().position(|&b| b == b'=') else { return ret_int(Err(sys::EINVAL)) };
    PUTENV.with(|entries, n| {
        // replace an entry for the same name
        for e in entries[..*n].iter_mut() {
            if unsafe { env_value(*e as *const u8, &s[..eq]) }.is_some() {
                *e = string as usize;
                return 0;
            }
        }
        if *n == entries.len() {
            return ret_int(Err(sys::ENOMEM));
        }
        entries[*n] = string as usize;
        *n += 1;
        0
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getenv(name: *const c_char) -> *mut c_char {
    let name = unsafe { CStr::from_ptr(name) }.to_bytes();
    if name.is_empty() || name.contains(&b'=') {
        return core::ptr::null_mut();
    }
    let added = PUTENV.with(|entries, n| entries[..*n].iter().rev().find_map(|&e| unsafe { env_value(e as *const u8, name) }));
    if let Some(v) = added {
        return v;
    }
    let mut p = start::envp();
    if p.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        while !(*p).is_null() {
            if let Some(v) = env_value(*p, name) {
                return v;
            }
            p = p.add(1);
        }
    }
    core::ptr::null_mut()
}

// ---- sysconf ----

const _SC_ARG_MAX: c_int = 0;
const _SC_CHILD_MAX: c_int = 1;
const _SC_CLK_TCK: c_int = 2;
const _SC_NGROUPS_MAX: c_int = 3;
const _SC_OPEN_MAX: c_int = 4;
const _SC_PAGESIZE: c_int = 30;
const _SC_GETGR_R_SIZE_MAX: c_int = 69;
const _SC_GETPW_R_SIZE_MAX: c_int = 70;
const _SC_NPROCESSORS_CONF: c_int = 83;
const _SC_NPROCESSORS_ONLN: c_int = 84;
const _SC_PHYS_PAGES: c_int = 85;
const _SC_HOST_NAME_MAX: c_int = 180;

const RLIMIT_NPROC: usize = 6;
const RLIMIT_NOFILE: usize = 7;
const RLIM_INFINITY: u64 = !0;

/// The soft limit of `resource`, as a `sysconf` value (-1 for unlimited).
fn soft_limit(resource: usize) -> c_long {
    let mut lim = [0u64; 2];
    match unsafe { sys::syscall(nr::PRLIMIT64, [0, resource, 0, lim.as_mut_ptr() as usize, 0, 0]) } {
        Ok(_) if lim[0] != RLIM_INFINITY => lim[0].min(c_long::MAX as u64) as c_long,
        _ => -1,
    }
}

/// The number of CPUs the process may run on.
fn cpus() -> c_long {
    let mut mask = [0u8; 128];
    match unsafe { sys::sched_getaffinity(mask.as_mut_ptr(), mask.len()) } {
        Ok(n) => mask[..n].iter().map(|b| b.count_ones() as c_long).sum::<c_long>().max(1),
        Err(_) => 1,
    }
}

fn page_size() -> usize {
    start::auxv(start::AT_PAGESZ).unwrap_or(sys::PAGE_SIZE)
}

#[unsafe(no_mangle)]
pub extern "C" fn sysconf(name: c_int) -> c_long {
    match name {
        _SC_ARG_MAX => 131072,
        _SC_CHILD_MAX => soft_limit(RLIMIT_NPROC),
        _SC_CLK_TCK => 100,
        _SC_NGROUPS_MAX => 65536,
        _SC_OPEN_MAX => soft_limit(RLIMIT_NOFILE),
        _SC_PAGESIZE => page_size() as c_long,
        // no limit: callers pick a buffer size and grow it on ERANGE
        _SC_GETGR_R_SIZE_MAX | _SC_GETPW_R_SIZE_MAX => -1,
        _SC_NPROCESSORS_CONF | _SC_NPROCESSORS_ONLN => cpus(),
        _SC_PHYS_PAGES => {
            // `struct sysinfo`: totalram at 32, mem_unit at 104
            let mut si = [0u64; 16];
            match unsafe { sys::syscall(nr::SYSINFO, [si.as_mut_ptr() as usize, 0, 0, 0, 0, 0]) } {
                Ok(_) => {
                    let unit = (si[13] & 0xffff_ffff).max(1);
                    (si[4].saturating_mul(unit) / page_size() as u64) as c_long
                }
                Err(e) => ret(Err(e)) as c_long,
            }
        }
        _SC_HOST_NAME_MAX => 64,
        _ => ret(Err(sys::EINVAL)) as c_long,
    }
}

// ---- memory ----

const MAP_FAILED: *mut c_void = !0usize as *mut c_void;
const POSIX_MADV_DONTNEED: c_int = 4;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mmap(addr: *mut c_void, len: size_t, prot: c_int, flags: c_int, fd: c_int, off: i64) -> *mut c_void {
    match unsafe { sys::mmap(addr as usize, len, prot as usize, flags as usize, fd, off as usize) } {
        Ok(p) => p as *mut c_void,
        Err(e) => {
            set_errno(e);
            MAP_FAILED
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn munmap(addr: *mut c_void, len: size_t) -> c_int {
    ret_int(unsafe { sys::munmap(addr as usize, len) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mprotect(addr: *mut c_void, len: size_t, prot: c_int) -> c_int {
    ret_int(unsafe { sys::mprotect(addr as usize, len, prot as usize) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn madvise(addr: *mut c_void, len: size_t, advice: c_int) -> c_int {
    ret_int(unsafe { sys::syscall(nr::MADVISE, [addr as usize, len, advice as usize, 0, 0, 0]) })
}

/// Returns the error rather than setting `errno`, as POSIX says. Like
/// glibc, `POSIX_MADV_DONTNEED` does nothing: Linux's `MADV_DONTNEED`
/// discards the pages, which POSIX's does not allow.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn posix_madvise(addr: *mut c_void, len: size_t, advice: c_int) -> c_int {
    if advice == POSIX_MADV_DONTNEED {
        return 0;
    }
    match unsafe { sys::syscall(nr::MADVISE, [addr as usize, len, advice as usize, 0, 0, 0]) } {
        Ok(_) => 0,
        Err(e) => e,
    }
}

// ---- scheduling ----

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sched_getaffinity(pid: pid_t, size: size_t, mask: *mut c_void) -> c_int {
    match unsafe { sys::syscall(nr::SCHED_GETAFFINITY, [pid as usize, size, mask as usize, 0, 0, 0]) } {
        Ok(n) => {
            // the kernel writes its mask size; the rest is ours to clear
            unsafe { core::ptr::write_bytes(mask.cast::<u8>().add(n), 0, size - n) };
            0
        }
        Err(e) => ret_int(Err(e)),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sched_setaffinity(pid: pid_t, size: size_t, set: *const c_void) -> c_int {
    ret_int(unsafe { sys::syscall(nr::SCHED_SETAFFINITY, [pid as usize, size, set as usize, 0, 0, 0]) })
}

#[unsafe(no_mangle)]
pub extern "C" fn sched_yield() -> c_int {
    sys::sched_yield();
    0
}

// ---- polling ----

#[unsafe(no_mangle)]
pub unsafe extern "C" fn poll(fds: *mut c_void, n: c_ulong, timeout_ms: c_int) -> c_int {
    let ts = sys::Timespec { sec: (timeout_ms / 1000) as i64, nsec: (timeout_ms % 1000) as i64 * 1_000_000 };
    let tsp = if timeout_ms < 0 { core::ptr::null() } else { &raw const ts };
    ret_int(unsafe { sys::ppoll(fds.cast(), n as usize, tsp) })
}

/// On a copy of the timeout: the kernel writes the time left into it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ppoll(fds: *mut c_void, n: c_ulong, timeout: *const sys::Timespec, sigmask: *const c_void) -> c_int {
    let mut ts = (!timeout.is_null()).then(|| unsafe { timeout.read() });
    let tsp = ts.as_mut().map_or(core::ptr::null_mut(), |t| t as *mut sys::Timespec);
    // the kernel's sigset_t is 8 bytes
    ret_int(unsafe { sys::syscall(nr::PPOLL, [fds as usize, n as usize, tsp as usize, sigmask as usize, 8, 0]) })
}

#[unsafe(no_mangle)]
pub extern "C" fn epoll_create1(flags: c_int) -> c_int {
    ret_int(unsafe { sys::syscall(nr::EPOLL_CREATE1, [flags as usize, 0, 0, 0, 0, 0]) })
}

#[unsafe(no_mangle)]
pub extern "C" fn epoll_create(size: c_int) -> c_int {
    if size <= 0 {
        return ret_int(Err(sys::EINVAL));
    }
    epoll_create1(0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn epoll_ctl(epfd: c_int, op: c_int, fd: c_int, event: *mut c_void) -> c_int {
    ret_int(unsafe { sys::syscall(nr::EPOLL_CTL, [epfd as usize, op as usize, fd as usize, event as usize, 0, 0]) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn epoll_wait(epfd: c_int, events: *mut c_void, max: c_int, timeout_ms: c_int) -> c_int {
    let args = [epfd as usize, events as usize, max as usize, timeout_ms as usize, 0, 8];
    ret_int(unsafe { sys::syscall(nr::EPOLL_PWAIT, args) })
}

// ---- sockets ----

#[unsafe(no_mangle)]
pub unsafe extern "C" fn send(fd: c_int, buf: *const c_void, len: size_t, flags: c_int) -> ssize_t {
    ret(unsafe { sys::syscall(nr::SENDTO, [fd as usize, buf as usize, len, flags as usize, 0, 0]) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn recv(fd: c_int, buf: *mut c_void, len: size_t, flags: c_int) -> ssize_t {
    ret(unsafe { sys::syscall(nr::RECVFROM, [fd as usize, buf as usize, len, flags as usize, 0, 0]) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn socketpair(domain: c_int, ty: c_int, proto: c_int, fds: *mut c_int) -> c_int {
    ret_int(unsafe { sys::socketpair(domain as u16, ty as u32, proto as u32, fds.cast()) })
}

// ---- signals ----

/// musl's `sigset_t`: 1024 bits, of which the kernel uses the first 64.
type sigset_t = [u64; 16];

/// musl's `struct sigaction`.
#[repr(C)]
pub struct sigaction {
    pub sa_sigaction: usize,
    pub sa_mask: sigset_t,
    pub sa_flags: c_int,
    pub sa_restorer: usize,
}

const SA_RESTART: usize = 0x1000_0000;
const NSIG: c_int = 65;

fn valid_signal(sig: c_int) -> bool {
    (1..NSIG).contains(&sig)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigemptyset(set: *mut sigset_t) -> c_int {
    unsafe { set.write([0; 16]) };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigfillset(set: *mut sigset_t) -> c_int {
    unsafe { set.write([0; 16]) };
    unsafe { (*set)[0] = !0 };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigaddset(set: *mut sigset_t, sig: c_int) -> c_int {
    if !valid_signal(sig) {
        return ret_int(Err(sys::EINVAL));
    }
    unsafe { (*set)[0] |= 1 << (sig - 1) };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigdelset(set: *mut sigset_t, sig: c_int) -> c_int {
    if !valid_signal(sig) {
        return ret_int(Err(sys::EINVAL));
    }
    unsafe { (*set)[0] &= !(1 << (sig - 1)) };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigismember(set: *const sigset_t, sig: c_int) -> c_int {
    if !valid_signal(sig) {
        return ret_int(Err(sys::EINVAL));
    }
    (unsafe { (*set)[0] } >> (sig - 1) & 1) as c_int
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigaction(sig: c_int, act: *const sigaction, old: *mut sigaction) -> c_int {
    if !valid_signal(sig) {
        return ret_int(Err(sys::EINVAL));
    }
    let kact = unsafe { act.as_ref() }.map(|a| KSigaction {
        handler: a.sa_sigaction,
        // the kernel returns from handlers through our `rt_sigreturn`
        flags: a.sa_flags as c_uint as usize | sys::SA_RESTORER,
        restorer: crate::arch::restore_rt as unsafe extern "C" fn() -> ! as usize,
        mask: a.sa_mask[0],
    });
    let mut kold = KSigaction { handler: 0, flags: 0, restorer: 0, mask: 0 };
    let kact_ptr = kact.as_ref().map_or(core::ptr::null(), |k| k as *const KSigaction);
    if let Err(e) = unsafe { sys::rt_sigaction(sig as usize, kact_ptr, &mut kold) } {
        return ret_int(Err(e));
    }
    if let Some(old) = unsafe { old.as_mut() } {
        old.sa_sigaction = kold.handler;
        old.sa_mask = [0; 16];
        old.sa_mask[0] = kold.mask;
        old.sa_flags = kold.flags as c_int;
        old.sa_restorer = kold.restorer;
    }
    0
}

const SIG_ERR: usize = !0;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn signal(sig: c_int, handler: usize) -> usize {
    let act = sigaction { sa_sigaction: handler, sa_mask: [0; 16], sa_flags: SA_RESTART as c_int, sa_restorer: 0 };
    let mut old = sigaction { sa_sigaction: 0, sa_mask: [0; 16], sa_flags: 0, sa_restorer: 0 };
    if unsafe { sigaction(sig, &act, &mut old) } < 0 { SIG_ERR } else { old.sa_sigaction }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigprocmask(how: c_int, set: *const sigset_t, old: *mut sigset_t) -> c_int {
    let mut kold = 0u64;
    let kset = unsafe { set.as_ref() }.map(|s| s[0]);
    let kset_ptr = kset.as_ref().map_or(core::ptr::null(), |k| k as *const u64);
    if let Err(e) = unsafe { sys::rt_sigprocmask(how as usize, kset_ptr, &mut kold) } {
        return ret_int(Err(e));
    }
    if let Some(old) = unsafe { old.as_mut() } {
        *old = [0; 16];
        old[0] = kold;
    }
    0
}

/// Returns the error rather than setting `errno`, as POSIX says.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_sigmask(how: c_int, set: *const sigset_t, old: *mut sigset_t) -> c_int {
    if unsafe { sigprocmask(how, set, old) } < 0 { unsafe { *errno::location() } } else { 0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn raise(sig: c_int) -> c_int {
    ret_int(sys::tgkill(sys::getpid(), sys::gettid(), sig as usize))
}

#[unsafe(no_mangle)]
pub extern "C" fn kill(pid: pid_t, sig: c_int) -> c_int {
    ret_int(sys::kill(pid, sig as usize))
}

#[unsafe(no_mangle)]
pub extern "C" fn abort() -> ! {
    start::abort()
}

// ---- semaphores ----

/// musl's `sem_t` is eight ints; the first is the count.
#[repr(C)]
pub struct sem_t {
    count: AtomicU32,
    _rest: [c_int; 7],
}

const SEM_VALUE_MAX: u32 = i32::MAX as u32;
const EOVERFLOW: i32 = 75;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sem_init(sem: *mut sem_t, _pshared: c_int, value: c_uint) -> c_int {
    if value > SEM_VALUE_MAX {
        return ret_int(Err(sys::EINVAL));
    }
    unsafe { sem.write(sem_t { count: AtomicU32::new(value), _rest: [0; 7] }) };
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn sem_destroy(_sem: *mut sem_t) -> c_int {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sem_post(sem: *mut sem_t) -> c_int {
    let count = unsafe { &(*sem).count };
    if count.try_update(Ordering::Release, Ordering::Relaxed, |c| (c < SEM_VALUE_MAX).then_some(c + 1)).is_err() {
        return ret_int(Err(EOVERFLOW));
    }
    // shared futexes, so that process-shared semaphores work too
    let _ = unsafe { sys::futex(count.as_ptr(), sys::FUTEX_WAKE, 1, core::ptr::null()) };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sem_trywait(sem: *mut sem_t) -> c_int {
    let count = unsafe { &(*sem).count };
    match count.try_update(Ordering::Acquire, Ordering::Relaxed, |c| c.checked_sub(1)) {
        Ok(_) => 0,
        Err(_) => ret_int(Err(sys::EAGAIN)),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sem_wait(sem: *mut sem_t) -> c_int {
    let count = unsafe { &(*sem).count };
    loop {
        if count.try_update(Ordering::Acquire, Ordering::Relaxed, |c| c.checked_sub(1)).is_ok() {
            return 0;
        }
        futex::wait_shared(count, 0);
    }
}

// ---- users and groups ----

/// musl's `struct passwd`.
#[repr(C)]
pub struct passwd {
    pub pw_name: *mut c_char,
    pub pw_passwd: *mut c_char,
    pub pw_uid: uid_t,
    pub pw_gid: gid_t,
    pub pw_gecos: *mut c_char,
    pub pw_dir: *mut c_char,
    pub pw_shell: *mut c_char,
}

/// musl's `struct group`.
#[repr(C)]
pub struct group {
    pub gr_name: *mut c_char,
    pub gr_passwd: *mut c_char,
    pub gr_gid: gid_t,
    pub gr_mem: *mut *mut c_char,
}

/// Run `f` on the contents of the file at `path`, mapped read-only.
fn with_file<R>(path: &CStr, f: impl FnOnce(&[u8]) -> R) -> SysResult<R> {
    let fd = unsafe { sys::openat(AT_FDCWD, path.as_ptr().cast(), sys::O_RDONLY | sys::O_CLOEXEC, 0)? };
    let size = sys::lseek(fd, 0, 2 /* SEEK_END */);
    let r = size.and_then(|size| {
        if size == 0 {
            return Ok(f(&[]));
        }
        let p = unsafe { sys::mmap(0, size, sys::PROT_READ, sys::MAP_PRIVATE, fd, 0)? };
        let r = f(unsafe { core::slice::from_raw_parts(p as *const u8, size) });
        let _ = unsafe { sys::munmap(p, size) };
        Ok(r)
    });
    let _ = sys::close(fd);
    r
}

use crate::passwd::parse_uid as parse_id;

/// Which entry to look up: by name or by id.
#[derive(Clone, Copy)]
enum Key<'a> {
    Name(&'a [u8]),
    Id(u32),
}

/// The `:`-separated fields of the first line of `file` with `N` fields
/// whose name (field 0) or id (field 2) matches `key`.
fn find_entry<'f, const N: usize>(file: &'f [u8], key: Key<'_>) -> Option<[&'f [u8]; N]> {
    file.split(|&b| b == b'\n').find_map(|line| {
        let mut fields = [&[][..]; N];
        let mut it = line.split(|&b| b == b':');
        for f in fields.iter_mut() {
            *f = it.next()?;
        }
        let hit = match key {
            Key::Name(n) => fields[0] == n,
            Key::Id(id) => parse_id(fields[2]) == Some(id),
        };
        hit.then_some(fields)
    })
}

/// Copies strings into a caller's buffer, NUL-terminated.
struct Buf {
    p: *mut u8,
    left: usize,
}

impl Buf {
    /// Align the next allocation to `align`.
    fn align(&mut self, align: usize) -> Option<()> {
        let pad = (self.p as usize).next_multiple_of(align) - self.p as usize;
        self.left = self.left.checked_sub(pad)?;
        self.p = unsafe { self.p.add(pad) };
        Some(())
    }

    fn take(&mut self, n: usize) -> Option<*mut u8> {
        self.left = self.left.checked_sub(n)?;
        let p = self.p;
        self.p = unsafe { self.p.add(n) };
        Some(p)
    }

    fn str(&mut self, s: &[u8]) -> Option<*mut c_char> {
        let p = self.take(s.len() + 1)?;
        unsafe {
            core::ptr::copy_nonoverlapping(s.as_ptr(), p, s.len());
            *p.add(s.len()) = 0;
        }
        Some(p.cast())
    }
}

const ERANGE: c_int = sys::ERANGE;

/// The `getpw*_r` and `getgr*_r` convention: 0 with `*result` set (or null
/// when there is no such entry), or an error number.
fn lookup_r<T>(file: &CStr, fill: impl FnOnce(&[u8]) -> Option<Option<T>>, out: *mut T, result: *mut *mut T) -> c_int {
    unsafe { *result = core::ptr::null_mut() };
    match with_file(file, fill) {
        Ok(Some(Some(v))) => {
            unsafe {
                out.write(v);
                *result = out;
            }
            0
        }
        Ok(Some(None)) => 0,
        Ok(None) => ERANGE,
        // no database: no such entry
        Err(sys::ENOENT) => 0,
        Err(e) => e,
    }
}

/// Some(None) when there is no entry, None when `buf` is too small.
fn fill_passwd(file: &[u8], key: Key<'_>, buf: &mut Buf) -> Option<Option<passwd>> {
    let Some([name, pw, uid, gid, gecos, dir, shell]) = find_entry::<7>(file, key) else { return Some(None) };
    Some(Some(passwd {
        pw_name: buf.str(name)?,
        pw_passwd: buf.str(pw)?,
        pw_uid: parse_id(uid).unwrap_or(0),
        pw_gid: parse_id(gid).unwrap_or(0),
        pw_gecos: buf.str(gecos)?,
        pw_dir: buf.str(dir)?,
        pw_shell: buf.str(shell)?,
    }))
}

fn fill_group(file: &[u8], key: Key<'_>, buf: &mut Buf) -> Option<Option<group>> {
    let Some([name, pw, gid, members]) = find_entry::<4>(file, key) else { return Some(None) };
    let members = || members.split(|&b| b == b',').filter(|m| !m.is_empty());
    buf.align(align_of::<*mut c_char>())?;
    let n = members().count();
    let mem = buf.take((n + 1) * size_of::<*mut c_char>())? as *mut *mut c_char;
    for (i, m) in members().enumerate() {
        unsafe { *mem.add(i) = buf.str(m)? };
    }
    unsafe { *mem.add(n) = core::ptr::null_mut() };
    Some(Some(group { gr_name: buf.str(name)?, gr_passwd: buf.str(pw)?, gr_gid: parse_id(gid).unwrap_or(0), gr_mem: mem }))
}

unsafe fn pw_r(key: Key<'_>, pwd: *mut passwd, buf: *mut c_char, len: size_t, result: *mut *mut passwd) -> c_int {
    let mut b = Buf { p: buf.cast(), left: len };
    lookup_r(c"/etc/passwd", |f| fill_passwd(f, key, &mut b), pwd, result)
}

unsafe fn gr_r(key: Key<'_>, grp: *mut group, buf: *mut c_char, len: size_t, result: *mut *mut group) -> c_int {
    let mut b = Buf { p: buf.cast(), left: len };
    lookup_r(c"/etc/group", |f| fill_group(f, key, &mut b), grp, result)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpwuid_r(uid: uid_t, pwd: *mut passwd, buf: *mut c_char, len: size_t, result: *mut *mut passwd) -> c_int {
    unsafe { pw_r(Key::Id(uid), pwd, buf, len, result) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpwnam_r(
    name: *const c_char,
    pwd: *mut passwd,
    buf: *mut c_char,
    len: size_t,
    result: *mut *mut passwd,
) -> c_int {
    unsafe { pw_r(Key::Name(CStr::from_ptr(name).to_bytes()), pwd, buf, len, result) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getgrgid_r(gid: gid_t, grp: *mut group, buf: *mut c_char, len: size_t, result: *mut *mut group) -> c_int {
    unsafe { gr_r(Key::Id(gid), grp, buf, len, result) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getgrnam_r(
    name: *const c_char,
    grp: *mut group,
    buf: *mut c_char,
    len: size_t,
    result: *mut *mut group,
) -> c_int {
    unsafe { gr_r(Key::Name(CStr::from_ptr(name).to_bytes()), grp, buf, len, result) }
}

/// The static storage of `getpwnam`, `getpwuid`, `getgrnam` and `getgrgid`,
/// which (as in C) later calls overwrite.
static mut PW: passwd = passwd {
    pw_name: core::ptr::null_mut(),
    pw_passwd: core::ptr::null_mut(),
    pw_uid: 0,
    pw_gid: 0,
    pw_gecos: core::ptr::null_mut(),
    pw_dir: core::ptr::null_mut(),
    pw_shell: core::ptr::null_mut(),
};
static mut GR: group = group { gr_name: core::ptr::null_mut(), gr_passwd: core::ptr::null_mut(), gr_gid: 0, gr_mem: core::ptr::null_mut() };
static mut STATIC_BUF: [u64; 512] = [0; 512];

/// The non-reentrant form of a `_r` lookup, on the static storage.
unsafe fn non_reentrant<T>(r: impl FnOnce(*mut c_char, size_t, *mut *mut T) -> c_int) -> *mut T {
    let mut result = core::ptr::null_mut();
    match r((&raw mut STATIC_BUF).cast(), size_of::<[u64; 512]>(), &mut result) {
        0 => result,
        e => {
            set_errno(e);
            core::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpwuid(uid: uid_t) -> *mut passwd {
    unsafe { non_reentrant(|b, l, r| getpwuid_r(uid, &raw mut PW, b, l, r)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpwnam(name: *const c_char) -> *mut passwd {
    unsafe { non_reentrant(|b, l, r| getpwnam_r(name, &raw mut PW, b, l, r)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getgrgid(gid: gid_t) -> *mut group {
    unsafe { non_reentrant(|b, l, r| getgrgid_r(gid, &raw mut GR, b, l, r)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getgrnam(name: *const c_char) -> *mut group {
    unsafe { non_reentrant(|b, l, r| getgrnam_r(name, &raw mut GR, b, l, r)) }
}

// ---- processes ----

#[unsafe(no_mangle)]
pub extern "C" fn fork() -> pid_t {
    // a child with a copy of the address space, like the kernel's fork
    pthread::with_handlers(|| ret(unsafe { sys::syscall(nr::CLONE, [sys::SIGCHLD, 0, 0, 0, 0, 0]) })) as pid_t
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn waitpid(pid: pid_t, status: *mut c_int, options: c_int) -> pid_t {
    ret_int(unsafe { sys::syscall(nr::WAIT4, [pid as usize, status as usize, options as usize, 0, 0, 0]) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wait4(pid: pid_t, status: *mut c_int, options: c_int, rusage: *mut c_void) -> pid_t {
    ret_int(unsafe { sys::syscall(nr::WAIT4, [pid as usize, status as usize, options as usize, rusage as usize, 0, 0]) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn execve(path: *const c_char, argv: *const *const c_char, envp: *const *const c_char) -> c_int {
    ret_int(unsafe { sys::syscall(nr::EXECVE, [path as usize, argv as usize, envp as usize, 0, 0, 0]) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn execv(path: *const c_char, argv: *const *const c_char) -> c_int {
    unsafe { execve(path, argv, start::envp().cast()) }
}

/// `execvp`: `file` as a path if it has a `/`, else searched for in `$PATH`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn execvp(file: *const c_char, argv: *const *const c_char) -> c_int {
    let name = unsafe { CStr::from_ptr(file) }.to_bytes();
    if name.is_empty() {
        return ret_int(Err(sys::ENOENT));
    }
    if name.contains(&b'/') {
        return unsafe { execv(file, argv) };
    }
    let path = unsafe { getenv(c"PATH".as_ptr()) };
    let path = if path.is_null() { b"/usr/local/bin:/bin:/usr/bin" } else { unsafe { CStr::from_ptr(path) }.to_bytes() };
    let mut err = sys::ENOENT;
    let mut full = [0u8; 4096];
    for dir in path.split(|&b| b == b':') {
        let dir = if dir.is_empty() { &b"."[..] } else { dir };
        let len = dir.len() + 1 + name.len();
        if len >= full.len() {
            err = sys::ENAMETOOLONG;
            continue;
        }
        full[..dir.len()].copy_from_slice(dir);
        full[dir.len()] = b'/';
        full[dir.len() + 1..len].copy_from_slice(name);
        full[len] = 0;
        unsafe { execv(full.as_ptr().cast(), argv) };
        // keep looking past directories without it; remember why it failed
        match unsafe { *errno::location() } {
            sys::ENOENT | sys::ENOTDIR => {}
            e => err = e,
        }
    }
    ret_int(Err(err))
}

// ---- dynamic linking (there is none) ----

/// glibc's and musl's `struct dl_phdr_info`.
#[repr(C)]
pub struct dl_phdr_info {
    pub dlpi_addr: usize,
    pub dlpi_name: *const c_char,
    pub dlpi_phdr: *const elf::Phdr,
    pub dlpi_phnum: u16,
    pub dlpi_adds: u64,
    pub dlpi_subs: u64,
    pub dlpi_tls_modid: usize,
    pub dlpi_tls_data: *mut c_void,
}

/// Calls `callback` for the one object loaded: the executable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dl_iterate_phdr(
    callback: Option<unsafe extern "C" fn(*mut dl_phdr_info, size_t, *mut c_void) -> c_int>,
    data: *mut c_void,
) -> c_int {
    let Some(callback) = callback else { return 0 };
    let phdrs = elf::program_headers();
    let mut info = dl_phdr_info {
        dlpi_addr: elf::executable_bias(),
        dlpi_name: c"".as_ptr(),
        dlpi_phdr: phdrs.as_ptr(),
        dlpi_phnum: phdrs.len() as u16,
        dlpi_adds: 1,
        dlpi_subs: 0,
        dlpi_tls_modid: 0,
        dlpi_tls_data: core::ptr::null_mut(),
    };
    unsafe { callback(&mut info, size_of::<dl_phdr_info>(), data) }
}

/// No shared objects, so no symbols to find: callers fall back as they do
/// when an optional symbol is missing.
#[unsafe(no_mangle)]
pub extern "C" fn dlsym(_handle: *mut c_void, _name: *const c_char) -> *mut c_void {
    core::ptr::null_mut()
}

#[unsafe(no_mangle)]
pub extern "C" fn dlopen(_path: *const c_char, _flags: c_int) -> *mut c_void {
    core::ptr::null_mut()
}

#[unsafe(no_mangle)]
pub extern "C" fn dlclose(_handle: *mut c_void) -> c_int {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn dlerror() -> *mut c_char {
    c"dynamic linking is not supported".as_ptr() as *mut c_char
}

// ---- more file descriptors ----

#[unsafe(no_mangle)]
pub extern "C" fn fcntl(fd: c_int, cmd: c_int, arg: usize) -> c_int {
    ret_int(sys::fcntl(fd, cmd as u32, arg))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pread(fd: c_int, buf: *mut c_void, n: size_t, off: i64) -> ssize_t {
    ret(unsafe { sys::pread(fd, buf.cast(), n, off as u64) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pwrite(fd: c_int, buf: *const c_void, n: size_t, off: i64) -> ssize_t {
    ret(unsafe { sys::pwrite(fd, buf.cast(), n, off as u64) })
}

#[unsafe(no_mangle)]
pub extern "C" fn fchmod(fd: c_int, mode: c_uint) -> c_int {
    ret_int(sys::fchmod(fd, mode))
}

#[unsafe(no_mangle)]
pub extern "C" fn umask(mask: c_uint) -> c_uint {
    (unsafe { sys::syscall(nr::UMASK, [mask as usize, 0, 0, 0, 0, 0]) }).unwrap_or(0) as c_uint
}

const AT_SYMLINK_NOFOLLOW: c_int = 0x100;
const AT_EMPTY_PATH: c_int = 0x1000;

/// `struct stat` is the kernel's on x86_64 and aarch64, in musl as here.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fstatat(dirfd: c_int, path: *const c_char, st: *mut c_void, flags: c_int) -> c_int {
    ret_int(unsafe { sys::syscall(nr::NEWFSTATAT, [dirfd as usize, path as usize, st as usize, flags as usize, 0, 0]) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn stat(path: *const c_char, st: *mut c_void) -> c_int {
    unsafe { fstatat(AT_FDCWD, path, st, 0) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lstat(path: *const c_char, st: *mut c_void) -> c_int {
    unsafe { fstatat(AT_FDCWD, path, st, AT_SYMLINK_NOFOLLOW) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fstat(fd: c_int, st: *mut c_void) -> c_int {
    unsafe { fstatat(fd, c"".as_ptr(), st, AT_EMPTY_PATH) }
}

/// musl's `struct statvfs`.
#[repr(C)]
pub struct statvfs {
    pub f_bsize: c_ulong,
    pub f_frsize: c_ulong,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_favail: u64,
    pub f_fsid: c_ulong,
    pub f_flag: c_ulong,
    pub f_namemax: c_ulong,
    __f_spare: [c_int; 6],
}

/// The kernel's `struct statfs` on 64-bit targets.
#[repr(C)]
struct KStatfs {
    f_type: i64,
    f_bsize: i64,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [i32; 2],
    f_namelen: i64,
    f_frsize: i64,
    f_flags: i64,
    f_spare: [i64; 4],
}

/// `statvfs` from `statfs`, as musl converts it.
fn to_statvfs(k: &KStatfs, out: *mut statvfs) {
    const ST_VALID: i64 = 0x20;
    let v = statvfs {
        f_bsize: k.f_bsize as c_ulong,
        f_frsize: if k.f_frsize != 0 { k.f_frsize } else { k.f_bsize } as c_ulong,
        f_blocks: k.f_blocks,
        f_bfree: k.f_bfree,
        f_bavail: k.f_bavail,
        f_files: k.f_files,
        f_ffree: k.f_ffree,
        f_favail: k.f_ffree,
        f_fsid: k.f_fsid[0] as u32 as c_ulong,
        f_flag: (k.f_flags & !ST_VALID) as c_ulong,
        f_namemax: k.f_namelen as c_ulong,
        __f_spare: [0; 6],
    };
    unsafe { out.write(v) };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn statvfs(path: *const c_char, out: *mut statvfs) -> c_int {
    let mut k = unsafe { core::mem::zeroed::<KStatfs>() };
    if let Err(e) = unsafe { sys::syscall(nr::STATFS, [path as usize, &raw mut k as usize, 0, 0, 0, 0]) } {
        return ret_int(Err(e));
    }
    to_statvfs(&k, out);
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fstatvfs(fd: c_int, out: *mut statvfs) -> c_int {
    let mut k = unsafe { core::mem::zeroed::<KStatfs>() };
    if let Err(e) = unsafe { sys::syscall(nr::FSTATFS, [fd as usize, &raw mut k as usize, 0, 0, 0, 0]) } {
        return ret_int(Err(e));
    }
    to_statvfs(&k, out);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn eventfd(initval: c_uint, flags: c_int) -> c_int {
    ret_int(unsafe { sys::syscall(nr::EVENTFD2, [initval as usize, flags as usize, 0, 0, 0, 0]) })
}

#[unsafe(no_mangle)]
pub extern "C" fn inotify_init1(flags: c_int) -> c_int {
    ret_int(unsafe { sys::syscall(nr::INOTIFY_INIT1, [flags as usize, 0, 0, 0, 0, 0]) })
}

#[unsafe(no_mangle)]
pub extern "C" fn inotify_init() -> c_int {
    inotify_init1(0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn inotify_add_watch(fd: c_int, path: *const c_char, mask: u32) -> c_int {
    ret_int(unsafe { sys::syscall(nr::INOTIFY_ADD_WATCH, [fd as usize, path as usize, mask as usize, 0, 0, 0]) })
}

#[unsafe(no_mangle)]
pub extern "C" fn inotify_rm_watch(fd: c_int, wd: c_int) -> c_int {
    ret_int(unsafe { sys::syscall(nr::INOTIFY_RM_WATCH, [fd as usize, wd as usize, 0, 0, 0, 0]) })
}

// ---- terminals ----

const TCSETS: usize = 0x5402;
const TCFLSH: usize = 0x540B;
const TCSBRK: usize = 0x5409;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn tcgetattr(fd: c_int, termios: *mut c_void) -> c_int {
    ret_int(unsafe { sys::ioctl(fd, TCGETS, termios as usize) })
}

/// `optional_actions` is `TCSANOW` (0), `TCSADRAIN` (1) or `TCSAFLUSH` (2),
/// which select `TCSETS`, `TCSETSW` and `TCSETSF`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tcsetattr(fd: c_int, optional_actions: c_int, termios: *const c_void) -> c_int {
    if !(0..=2).contains(&optional_actions) {
        return ret_int(Err(sys::EINVAL));
    }
    ret_int(unsafe { sys::ioctl(fd, TCSETS + optional_actions as usize, termios as usize) })
}

#[unsafe(no_mangle)]
pub extern "C" fn tcflush(fd: c_int, queue: c_int) -> c_int {
    ret_int(unsafe { sys::ioctl(fd, TCFLSH, queue as usize) })
}

/// Waits until the output is sent: `TCSBRK` with a nonzero argument sends
/// no break, only drains.
#[unsafe(no_mangle)]
pub extern "C" fn tcdrain(fd: c_int) -> c_int {
    ret_int(unsafe { sys::ioctl(fd, TCSBRK, 1) })
}

// ---- more sockets ----

#[unsafe(no_mangle)]
pub extern "C" fn socket(domain: c_int, ty: c_int, proto: c_int) -> c_int {
    ret_int(unsafe { sys::syscall(nr::SOCKET, [domain as usize, ty as usize, proto as usize, 0, 0, 0]) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect(fd: c_int, addr: *const c_void, len: u32) -> c_int {
    ret_int(unsafe { sys::syscall(nr::CONNECT, [fd as usize, addr as usize, len as usize, 0, 0, 0]) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bind(fd: c_int, addr: *const c_void, len: u32) -> c_int {
    ret_int(unsafe { sys::syscall(nr::BIND, [fd as usize, addr as usize, len as usize, 0, 0, 0]) })
}

#[unsafe(no_mangle)]
pub extern "C" fn listen(fd: c_int, backlog: c_int) -> c_int {
    ret_int(unsafe { sys::syscall(nr::LISTEN, [fd as usize, backlog as usize, 0, 0, 0, 0]) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn accept4(fd: c_int, addr: *mut c_void, len: *mut u32, flags: c_int) -> c_int {
    ret_int(unsafe { sys::syscall(nr::ACCEPT4, [fd as usize, addr as usize, len as usize, flags as usize, 0, 0]) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn accept(fd: c_int, addr: *mut c_void, len: *mut u32) -> c_int {
    unsafe { accept4(fd, addr, len, 0) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn setsockopt(fd: c_int, level: c_int, name: c_int, val: *const c_void, len: u32) -> c_int {
    let args = [fd as usize, level as usize, name as usize, val as usize, len as usize, 0];
    ret_int(unsafe { sys::syscall(nr::SETSOCKOPT, args) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getsockopt(fd: c_int, level: c_int, name: c_int, val: *mut c_void, len: *mut u32) -> c_int {
    let args = [fd as usize, level as usize, name as usize, val as usize, len as usize, 0];
    ret_int(unsafe { sys::syscall(nr::GETSOCKOPT, args) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sendmsg(fd: c_int, msg: *const c_void, flags: c_int) -> ssize_t {
    ret(unsafe { sys::sendmsg(fd, msg.cast(), flags as u32) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn recvmsg(fd: c_int, msg: *mut c_void, flags: c_int) -> ssize_t {
    ret(unsafe { sys::recvmsg(fd, msg.cast(), flags as u32) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sendmmsg(fd: c_int, msgs: *mut c_void, n: c_uint, flags: c_int) -> c_int {
    ret_int(unsafe { sys::syscall(nr::SENDMMSG, [fd as usize, msgs as usize, n as usize, flags as usize, 0, 0]) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn recvmmsg(fd: c_int, msgs: *mut c_void, n: c_uint, flags: c_int, timeout: *mut sys::Timespec) -> c_int {
    let args = [fd as usize, msgs as usize, n as usize, flags as usize, timeout as usize, 0];
    ret_int(unsafe { sys::syscall(nr::RECVMMSG, args) })
}

/// The index of the network interface `name`, by `SIOCGIFINDEX` on a
/// socket; 0 (with `errno` set) if there is none.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn if_nametoindex(name: *const c_char) -> c_uint {
    const SIOCGIFINDEX: usize = 0x8933;
    // struct ifreq: the name, then a union (the index first)
    let mut ifr = [0u8; 40];
    let name = unsafe { core::ffi::CStr::from_ptr(name) }.to_bytes();
    if name.len() >= 16 {
        set_errno(sys::ENODEV);
        return 0;
    }
    ifr[..name.len()].copy_from_slice(name);
    let fd = match sys::socket(sys::AF_INET, sys::SOCK_DGRAM | sys::SOCK_CLOEXEC, 0) {
        Ok(fd) => fd,
        Err(e) => {
            set_errno(e);
            return 0;
        }
    };
    let r = unsafe { sys::ioctl(fd, SIOCGIFINDEX, ifr.as_mut_ptr() as usize) };
    let _ = sys::close(fd);
    match r {
        Ok(_) => i32::from_ne_bytes(ifr[16..20].try_into().unwrap()) as c_uint,
        Err(e) => {
            set_errno(e);
            0
        }
    }
}

// ---- more signals, time and resources ----

/// Returns the error rather than setting `errno`, as POSIX says.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigwait(set: *const sigset_t, sig: *mut c_int) -> c_int {
    loop {
        let args = [set as usize, 0, 0, 8, 0, 0];
        match unsafe { sys::syscall(nr::RT_SIGTIMEDWAIT, args) } {
            Ok(s) => {
                unsafe { *sig = s as c_int };
                return 0;
            }
            Err(sys::EINTR) => {}
            Err(e) => return e,
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn clock_gettime(clock: c_int, ts: *mut sys::Timespec) -> c_int {
    ret_int(unsafe { sys::syscall(nr::CLOCK_GETTIME, [clock as usize, ts as usize, 0, 0, 0, 0]) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getrusage(who: c_int, usage: *mut c_void) -> c_int {
    ret_int(unsafe { sys::syscall(nr::GETRUSAGE, [who as usize, usage as usize, 0, 0, 0, 0]) })
}

/// `struct sysinfo` is the kernel's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getrlimit(resource: c_int, rlim: *mut [u64; 2]) -> c_int {
    ret_int(unsafe { sys::syscall(nr::PRLIMIT64, [0, resource as usize, 0, rlim as usize, 0, 0]) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn setrlimit(resource: c_int, rlim: *const [u64; 2]) -> c_int {
    ret_int(unsafe { sys::syscall(nr::PRLIMIT64, [0, resource as usize, rlim as usize, 0, 0, 0]) })
}

/// Listing interfaces takes a netlink client, which there is not: callers
/// get `ENOSYS`, as from a kernel without the feature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getifaddrs(ifap: *mut *mut c_void) -> c_int {
    unsafe { *ifap = core::ptr::null_mut() };
    ret_int(Err(sys::ENOSYS))
}

#[unsafe(no_mangle)]
pub extern "C" fn freeifaddrs(_ifa: *mut c_void) {}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sysinfo(info: *mut c_void) -> c_int {
    ret_int(unsafe { sys::syscall(nr::SYSINFO, [info as usize, 0, 0, 0, 0, 0]) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn prctl(op: c_int, a: c_ulong, b: c_ulong, c: c_ulong, d: c_ulong) -> c_int {
    ret_int(unsafe { sys::prctl(op as usize, a as usize, b as usize, c as usize, d as usize) })
}

// ---- mount tables ----

/// A `FILE` for reading lines, enough for the `*mntent` functions, or for
/// the unbuffered writes of `stdio`.
pub struct FILE {
    fd: c_int,
    pos: usize,
    len: usize,
    buf: [u8; 4096],
    line: [u8; 4096],
}

/// Room for a `FILE`, from the kernel: there is no allocator here.
const FILE_PAGES: usize = size_of::<FILE>().next_multiple_of(sys::PAGE_SIZE);

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fopen(path: *const c_char, mode: *const c_char) -> *mut FILE {
    // only reading is supported
    if unsafe { *mode } != b'r' as c_char || unsafe { CStr::from_ptr(mode) }.to_bytes().contains(&b'+') {
        set_errno(sys::EINVAL);
        return core::ptr::null_mut();
    }
    let fd = match unsafe { sys::openat(AT_FDCWD, path.cast(), sys::O_RDONLY | sys::O_CLOEXEC, 0) } {
        Ok(fd) => fd,
        Err(e) => {
            set_errno(e);
            return core::ptr::null_mut();
        }
    };
    let rw = sys::PROT_READ | sys::PROT_WRITE;
    match unsafe { sys::mmap(0, FILE_PAGES, rw, sys::MAP_PRIVATE | sys::MAP_ANONYMOUS, -1, 0) } {
        Ok(p) => {
            let f = p as *mut FILE;
            unsafe {
                (*f).fd = fd;
                (*f).pos = 0;
                (*f).len = 0;
            }
            f
        }
        Err(e) => {
            let _ = sys::close(fd);
            set_errno(e);
            core::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fclose(f: *mut FILE) -> c_int {
    let r = sys::close(unsafe { (*f).fd });
    if !stdio::is_standard(f) {
        let _ = unsafe { sys::munmap(f as usize, FILE_PAGES) };
    }
    ret_int(r)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fileno(f: *mut FILE) -> c_int {
    unsafe { (*f).fd }
}

/// The next line of `f` without its newline (a longer one is cut short),
/// or None at the end of the file.
fn next_line(f: &mut FILE) -> Option<&[u8]> {
    let mut n = 0;
    loop {
        if f.pos == f.len {
            f.pos = 0;
            f.len = unsafe { sys::read(f.fd, f.buf.as_mut_ptr(), f.buf.len()) }.unwrap_or(0);
            if f.len == 0 {
                return (n > 0).then_some(&f.line[..n]);
            }
        }
        let b = f.buf[f.pos];
        f.pos += 1;
        if b == b'\n' {
            return Some(&f.line[..n]);
        }
        if n < f.line.len() {
            f.line[n] = b;
            n += 1;
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fgets(s: *mut c_char, size: c_int, f: *mut FILE) -> *mut c_char {
    let Some(line) = next_line(unsafe { &mut *f }) else { return core::ptr::null_mut() };
    if size <= 0 {
        return core::ptr::null_mut();
    }
    // the newline is kept, as far as there is room
    let n = line.len().min(size as usize - 1);
    unsafe {
        core::ptr::copy_nonoverlapping(line.as_ptr(), s.cast(), n);
        let mut end = n;
        if end < size as usize - 1 {
            *s.add(end) = b'\n' as c_char;
            end += 1;
        }
        *s.add(end) = 0;
    }
    s
}

/// glibc's and musl's `struct mntent`.
#[repr(C)]
pub struct mntent {
    pub mnt_fsname: *mut c_char,
    pub mnt_dir: *mut c_char,
    pub mnt_type: *mut c_char,
    pub mnt_opts: *mut c_char,
    pub mnt_freq: c_int,
    pub mnt_passno: c_int,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn setmntent(path: *const c_char, mode: *const c_char) -> *mut FILE {
    unsafe { fopen(path, mode) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn endmntent(f: *mut FILE) -> c_int {
    if !f.is_null() {
        unsafe { fclose(f) };
    }
    1
}

/// Copy a field of a mount table line into `buf`, decoding the `\ooo`
/// escapes of spaces, tabs, newlines and backslashes.
fn mnt_field(field: &[u8], buf: &mut Buf) -> Option<*mut c_char> {
    let p = buf.take(field.len() + 1)?;
    let mut n = 0;
    let mut i = 0;
    while i < field.len() {
        let oct = field.get(i + 1..i + 4).filter(|o| field[i] == b'\\' && o.iter().all(|d| (b'0'..=b'7').contains(d)));
        let b = match oct {
            Some(o) => {
                i += 4;
                (o[0] - b'0') << 6 | (o[1] - b'0') << 3 | (o[2] - b'0')
            }
            None => {
                i += 1;
                field[i - 1]
            }
        };
        unsafe { *p.add(n) = b };
        n += 1;
    }
    unsafe { *p.add(n) = 0 };
    Some(p.cast())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getmntent_r(f: *mut FILE, ent: *mut mntent, buf: *mut c_char, len: c_int) -> *mut mntent {
    let f = unsafe { &mut *f };
    loop {
        let Some(line) = next_line(f) else { return core::ptr::null_mut() };
        let mut fields = line.split(|b| b.is_ascii_whitespace()).filter(|s| !s.is_empty());
        let Some(fsname) = fields.next() else { continue };
        if fsname.starts_with(b"#") {
            continue;
        }
        let (dir, ty, opts) = (fields.next().unwrap_or(b""), fields.next().unwrap_or(b""), fields.next().unwrap_or(b""));
        let num = |s: Option<&[u8]>| s.and_then(parse_id).unwrap_or(0) as c_int;
        let (freq, passno) = (num(fields.next()), num(fields.next()));
        let mut b = Buf { p: buf.cast(), left: len.max(0) as usize };
        let filled = (|| {
            Some(mntent {
                mnt_fsname: mnt_field(fsname, &mut b)?,
                mnt_dir: mnt_field(dir, &mut b)?,
                mnt_type: mnt_field(ty, &mut b)?,
                mnt_opts: mnt_field(opts, &mut b)?,
                mnt_freq: freq,
                mnt_passno: passno,
            })
        })();
        // a line too long for `buf` is skipped, as in musl
        if let Some(m) = filled {
            unsafe { ent.write(m) };
            return ent;
        }
    }
}

static mut MNT: mntent = mntent {
    mnt_fsname: core::ptr::null_mut(),
    mnt_dir: core::ptr::null_mut(),
    mnt_type: core::ptr::null_mut(),
    mnt_opts: core::ptr::null_mut(),
    mnt_freq: 0,
    mnt_passno: 0,
};
static mut MNT_BUF: [u8; 4096] = [0; 4096];

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getmntent(f: *mut FILE) -> *mut mntent {
    unsafe { getmntent_r(f, &raw mut MNT, (&raw mut MNT_BUF).cast(), 4096) }
}

// ---- the C heap ----

/// A heap block: the user's pointer is preceded by its alignment and the
/// whole block's size, which free and realloc need for the layout.
static HEAP: crate::alloc::Allocator = crate::alloc::Allocator::new();

const HEADER: usize = 16;

unsafe fn heap_alloc(n: size_t, align: usize, zeroed: bool) -> *mut c_void {
    use core::alloc::{GlobalAlloc, Layout};
    let align = align.max(HEADER);
    let Some(layout) = n.checked_add(align).and_then(|total| Layout::from_size_align(total, align).ok()) else {
        set_errno(sys::ENOMEM);
        return core::ptr::null_mut();
    };
    let base = unsafe { if zeroed { HEAP.alloc_zeroed(layout) } else { HEAP.alloc(layout) } };
    if base.is_null() {
        set_errno(sys::ENOMEM);
        return core::ptr::null_mut();
    }
    unsafe {
        let p = base.add(align);
        p.cast::<usize>().sub(2).write(align);
        p.cast::<usize>().sub(1).write(layout.size());
        p.cast()
    }
}

/// The block's alignment and size, and its start.
unsafe fn heap_block(p: *mut c_void) -> (core::alloc::Layout, *mut u8) {
    unsafe {
        let align = p.cast::<usize>().sub(2).read();
        let total = p.cast::<usize>().sub(1).read();
        (core::alloc::Layout::from_size_align_unchecked(total, align), p.cast::<u8>().sub(align))
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn malloc(n: size_t) -> *mut c_void {
    unsafe { heap_alloc(n, HEADER, false) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn calloc(count: size_t, size: size_t) -> *mut c_void {
    match count.checked_mul(size) {
        Some(n) => unsafe { heap_alloc(n, HEADER, true) },
        None => {
            set_errno(sys::ENOMEM);
            core::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn free(p: *mut c_void) {
    use core::alloc::GlobalAlloc;
    if !p.is_null() {
        let (layout, base) = unsafe { heap_block(p) };
        unsafe { HEAP.dealloc(base, layout) }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn realloc(p: *mut c_void, n: size_t) -> *mut c_void {
    if p.is_null() {
        return unsafe { malloc(n) };
    }
    let (layout, _) = unsafe { heap_block(p) };
    let old = layout.size() - layout.align();
    let q = unsafe { heap_alloc(n, layout.align(), false) };
    if !q.is_null() {
        unsafe {
            core::ptr::copy_nonoverlapping(p.cast::<u8>(), q.cast::<u8>(), old.min(n));
            free(p);
        }
    }
    q
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn aligned_alloc(align: size_t, n: size_t) -> *mut c_void {
    if !align.is_power_of_two() {
        set_errno(sys::EINVAL);
        return core::ptr::null_mut();
    }
    unsafe { heap_alloc(n, align, false) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn posix_memalign(out: *mut *mut c_void, align: size_t, n: size_t) -> c_int {
    if !align.is_power_of_two() || align % size_of::<usize>() != 0 {
        return sys::EINVAL;
    }
    let p = unsafe { heap_alloc(n, align, false) };
    if p.is_null() {
        return sys::ENOMEM;
    }
    unsafe { *out = p };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn malloc_usable_size(p: *mut c_void) -> size_t {
    if p.is_null() {
        return 0;
    }
    let (layout, _) = unsafe { heap_block(p) };
    layout.size() - layout.align()
}

// ---- mutexes ----

/// musl's `pthread_mutex_t`, whose static initializer is all zeros; the
/// first word is the lock. Only normal (non-recursive) mutexes.
#[repr(C)]
pub struct pthread_mutex_t {
    lock: crate::locks::RawMutex,
    _rest: [c_int; 9],
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_init(m: *mut pthread_mutex_t, _attr: *const c_void) -> c_int {
    unsafe { m.write_bytes(0, 1) };
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn pthread_mutex_destroy(_m: *mut pthread_mutex_t) -> c_int {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_lock(m: *mut pthread_mutex_t) -> c_int {
    unsafe { (*m).lock.lock() };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_trylock(m: *mut pthread_mutex_t) -> c_int {
    if unsafe { (*m).lock.try_lock() } { 0 } else { sys::EBUSY }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_unlock(m: *mut pthread_mutex_t) -> c_int {
    unsafe { (*m).lock.unlock() };
    0
}

// ---- odds and ends ----

#[unsafe(no_mangle)]
pub extern "C" fn lseek(fd: c_int, off: i64, whence: c_int) -> i64 {
    ret(sys::lseek(fd, off, whence as u32)) as i64
}

/// The real-time signals musl leaves to programs: it keeps 32 to 34.
#[unsafe(no_mangle)]
pub extern "C" fn __libc_current_sigrtmin() -> c_int {
    35
}

#[unsafe(no_mangle)]
pub extern "C" fn __libc_current_sigrtmax() -> c_int {
    64
}

/// The XSI `strerror_r`, which is musl's; the messages are glibc's.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strerror_r(e: c_int, buf: *mut c_char, len: size_t) -> c_int {
    let msg = sys::strerror(e).as_bytes();
    if len == 0 {
        return sys::ERANGE;
    }
    let n = msg.len().min(len - 1);
    unsafe {
        core::ptr::copy_nonoverlapping(msg.as_ptr(), buf.cast::<u8>(), n);
        *buf.add(n) = 0;
    }
    if n < msg.len() { sys::ERANGE } else { 0 }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getsockname(fd: c_int, addr: *mut c_void, len: *mut u32) -> c_int {
    ret_int(unsafe { sys::getsockname(fd, addr.cast(), len) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpeername(fd: c_int, addr: *mut c_void, len: *mut u32) -> c_int {
    ret_int(unsafe { sys::getpeername(fd, addr.cast(), len) })
}

// ---- broken-down time ----

#[repr(C)]
pub struct tm {
    tm_sec: c_int,
    tm_min: c_int,
    tm_hour: c_int,
    tm_mday: c_int,
    tm_mon: c_int,
    tm_year: c_int,
    tm_wday: c_int,
    tm_yday: c_int,
    tm_isdst: c_int,
    tm_gmtoff: c_long,
    tm_zone: *const c_char,
}

/// The local time type of `t`, from the zone `$TZ` names, as musl finds
/// it: a file (under `$TZDIR` too) or a POSIX TZ string; `/etc/localtime`
/// without `$TZ`; UTC failing both. Read on each call.
fn local_at(t: i64) -> tz::Local {
    let from_file = |path: &CStr| with_file(path, |f| tz::tzif(f, t)).ok().flatten();
    let tz = unsafe { getenv(c"TZ".as_ptr()) };
    if tz.is_null() {
        return from_file(c"/etc/localtime").unwrap_or(tz::Local::UTC);
    }
    let tz = unsafe { CStr::from_ptr(tz) }.to_bytes();
    let tz = tz.strip_prefix(b":").unwrap_or(tz);
    let mut path = [0u8; 256];
    // the file dir/tz, or tz without a dir
    let mut file_at = |dir: &[u8]| {
        let sep = !dir.is_empty() as usize;
        let n = dir.len() + sep + tz.len();
        if n >= path.len() {
            return None;
        }
        path[..dir.len()].copy_from_slice(dir);
        path[dir.len()] = b'/';
        path[dir.len() + sep..n].copy_from_slice(tz);
        path[n] = 0;
        from_file(CStr::from_bytes_until_nul(&path).ok()?)
    };
    let found = if tz.starts_with(b"/") {
        file_at(b"")
    } else if tz.is_empty() || tz.windows(2).any(|w| w == b"..") {
        None
    } else {
        let tzdir = unsafe { getenv(c"TZDIR".as_ptr()) };
        let tzdir = (!tzdir.is_null()).then(|| unsafe { CStr::from_ptr(tzdir) }.to_bytes());
        tzdir
            .into_iter()
            .chain([&b"/usr/share/zoneinfo"[..], b"/share/zoneinfo", b"/etc/zoneinfo"])
            .find_map(&mut file_at)
    };
    found.or_else(|| tz::posix(tz, t)).unwrap_or(tz::Local::UTC)
}

/// The zone abbreviation `tm_zone` points to, until the thread's next call.
#[thread_local]
static mut ZONE: [u8; 8] = [0; 8];

unsafe fn fill_tm(t: i64, local: tz::Local, out: *mut tm) -> *mut tm {
    let secs = t + local.offset as i64;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (y, m, d) = tz::civil_from_days(days);
    let Ok(year) = c_int::try_from(y - 1900) else {
        set_errno(sys::EOVERFLOW);
        return core::ptr::null_mut();
    };
    unsafe {
        ZONE = local.abbr;
        out.write(tm {
            tm_sec: (rem % 60) as c_int,
            tm_min: (rem / 60 % 60) as c_int,
            tm_hour: (rem / 3600) as c_int,
            tm_mday: d as c_int,
            tm_mon: m as c_int - 1,
            tm_year: year,
            // 1970-01-01 was a Thursday
            tm_wday: (days + 4).rem_euclid(7) as c_int,
            tm_yday: (days - tz::days_from_civil(y, 1, 1)) as c_int,
            tm_isdst: local.isdst as c_int,
            tm_gmtoff: local.offset as c_long,
            tm_zone: (&raw const ZONE).cast(),
        });
    }
    out
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmtime_r(t: *const i64, out: *mut tm) -> *mut tm {
    unsafe { fill_tm(*t, tz::Local::UTC, out) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn localtime_r(t: *const i64, out: *mut tm) -> *mut tm {
    let t = unsafe { *t };
    unsafe { fill_tm(t, local_at(t), out) }
}

#[thread_local]
static mut TM: tm = tm {
    tm_sec: 0,
    tm_min: 0,
    tm_hour: 0,
    tm_mday: 0,
    tm_mon: 0,
    tm_year: 0,
    tm_wday: 0,
    tm_yday: 0,
    tm_isdst: 0,
    tm_gmtoff: 0,
    tm_zone: core::ptr::null(),
};

#[unsafe(no_mangle)]
pub unsafe extern "C" fn gmtime(t: *const i64) -> *mut tm {
    unsafe { gmtime_r(t, &raw mut TM) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn localtime(t: *const i64) -> *mut tm {
    unsafe { localtime_r(t, &raw mut TM) }
}

// ---- files and directories ----

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mkdir(path: *const c_char, mode: c_uint) -> c_int {
    ret_int(unsafe { sys::mkdirat(AT_FDCWD, path.cast(), mode) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rmdir(path: *const c_char) -> c_int {
    ret_int(unsafe { sys::unlinkat(AT_FDCWD, path.cast(), sys::AT_REMOVEDIR) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn unlink(path: *const c_char) -> c_int {
    ret_int(unsafe { sys::unlinkat(AT_FDCWD, path.cast(), 0) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn link(old: *const c_char, new: *const c_char) -> c_int {
    ret_int(unsafe { sys::linkat(AT_FDCWD, old.cast(), AT_FDCWD, new.cast(), 0) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rename(old: *const c_char, new: *const c_char) -> c_int {
    ret_int(unsafe { sys::renameat2(AT_FDCWD, old.cast(), AT_FDCWD, new.cast(), 0) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn chmod(path: *const c_char, mode: c_uint) -> c_int {
    ret_int(unsafe { sys::fchmodat(AT_FDCWD, path.cast(), mode) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn readlink(path: *const c_char, buf: *mut c_char, len: size_t) -> ssize_t {
    ret(unsafe { sys::readlinkat(AT_FDCWD, path.cast(), buf.cast(), len) })
}

#[unsafe(no_mangle)]
pub extern "C" fn fsync(fd: c_int) -> c_int {
    ret_int(sys::fsync(fd))
}

#[unsafe(no_mangle)]
pub extern "C" fn flock(fd: c_int, op: c_int) -> c_int {
    ret_int(sys::flock(fd, op as u32))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn mkfifo(path: *const c_char, mode: c_uint) -> c_int {
    ret_int(unsafe { sys::mknodat(AT_FDCWD, path.cast(), mode | sys::S_IFIFO, 0) })
}

#[repr(C)]
pub struct timeval {
    tv_sec: i64,
    tv_usec: i64,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn utimes(path: *const c_char, tv: *const [timeval; 2]) -> c_int {
    let ts = (!tv.is_null()).then(|| unsafe { (*tv).each_ref().map(|t| sys::Timespec { sec: t.tv_sec, nsec: t.tv_usec * 1000 }) });
    let p = ts.as_ref().map_or(core::ptr::null(), |t| t.as_ptr());
    ret_int(unsafe { sys::utimensat(AT_FDCWD, path.cast(), p, 0) })
}

/// The path the kernel has for an open file descriptor.
fn fd_path(fd: c_int, buf: &mut [u8]) -> SysResult<usize> {
    let mut proc = *b"/proc/self/fd/\0\0\0\0\0\0\0\0\0\0\0\0";
    let mut n = 14;
    let mut digits = [0u8; 11];
    let mut i = digits.len();
    let mut v = fd as u32;
    loop {
        i -= 1;
        digits[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for &d in &digits[i..] {
        proc[n] = d;
        n += 1;
    }
    let len = unsafe { sys::readlinkat(AT_FDCWD, proc.as_ptr(), buf.as_mut_ptr(), buf.len())? };
    if len == buf.len() {
        return Err(sys::ERANGE);
    }
    Ok(len)
}

const PATH_MAX: usize = 4096;

/// As musl's: the path the kernel gives the file once it is opened.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn realpath(path: *const c_char, resolved: *mut c_char) -> *mut c_char {
    let fd = match unsafe { sys::openat(AT_FDCWD, path.cast(), sys::O_PATH | sys::O_CLOEXEC, 0) } {
        Ok(fd) => fd,
        Err(e) => {
            set_errno(e);
            return core::ptr::null_mut();
        }
    };
    let mut buf = [0u8; PATH_MAX];
    let r = fd_path(fd, &mut buf[..PATH_MAX - 1]);
    let _ = sys::close(fd);
    let len = match r {
        Ok(n) => n,
        Err(e) => {
            set_errno(if e == sys::ERANGE { sys::ENAMETOOLONG } else { e });
            return core::ptr::null_mut();
        }
    };
    let out = if resolved.is_null() { unsafe { malloc(len + 1) }.cast::<u8>() } else { resolved.cast() };
    if out.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        core::ptr::copy_nonoverlapping(buf.as_ptr(), out, len);
        *out.add(len) = 0;
    }
    out.cast()
}

/// A directory stream: `readdir` returns the `getdents64` records in
/// `buf`, which are laid out as `struct dirent`.
pub struct DIR {
    fd: c_int,
    pos: usize,
    len: usize,
    buf: [u8; 32768],
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fdopendir(fd: c_int) -> *mut DIR {
    let d = unsafe { malloc(size_of::<DIR>()) }.cast::<DIR>();
    if !d.is_null() {
        unsafe {
            (*d).fd = fd;
            (*d).pos = 0;
            (*d).len = 0;
        }
    }
    d
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn opendir(path: *const c_char) -> *mut DIR {
    let flags = sys::O_RDONLY | sys::O_DIRECTORY | sys::O_CLOEXEC;
    let fd = match unsafe { sys::openat(AT_FDCWD, path.cast(), flags, 0) } {
        Ok(fd) => fd,
        Err(e) => {
            set_errno(e);
            return core::ptr::null_mut();
        }
    };
    let d = unsafe { fdopendir(fd) };
    if d.is_null() {
        let _ = sys::close(fd);
    }
    d
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn readdir(d: *mut DIR) -> *mut c_void {
    let d = unsafe { &mut *d };
    if d.pos >= d.len {
        match unsafe { sys::getdents64(d.fd, d.buf.as_mut_ptr(), d.buf.len()) } {
            Ok(0) => return core::ptr::null_mut(),
            Ok(n) => (d.pos, d.len) = (0, n),
            Err(e) => {
                set_errno(e);
                return core::ptr::null_mut();
            }
        }
    }
    let rec = d.buf[d.pos..].as_mut_ptr();
    // d_reclen, after d_ino and d_off
    d.pos += u16::from_ne_bytes([d.buf[d.pos + 16], d.buf[d.pos + 17]]) as usize;
    rec.cast()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn closedir(d: *mut DIR) -> c_int {
    let r = sys::close(unsafe { (*d).fd });
    unsafe { free(d.cast()) };
    ret_int(r)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dirfd(d: *mut DIR) -> c_int {
    unsafe { (*d).fd }
}

unsafe fn xattr(n: usize, path: *const c_char, name: *const c_char, v: *mut c_void, len: size_t) -> ssize_t {
    ret(unsafe { sys::syscall(n, [path as usize, name as usize, v as usize, len, 0, 0]) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getxattr(path: *const c_char, name: *const c_char, v: *mut c_void, len: size_t) -> ssize_t {
    unsafe { xattr(nr::GETXATTR, path, name, v, len) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lgetxattr(path: *const c_char, name: *const c_char, v: *mut c_void, len: size_t) -> ssize_t {
    unsafe { xattr(nr::LGETXATTR, path, name, v, len) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn listxattr(path: *const c_char, list: *mut c_char, len: size_t) -> ssize_t {
    ret(unsafe { sys::syscall(nr::LISTXATTR, [path as usize, list as usize, len, 0, 0, 0]) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn llistxattr(path: *const c_char, list: *mut c_char, len: size_t) -> ssize_t {
    ret(unsafe { sys::syscall(nr::LLISTXATTR, [path as usize, list as usize, len, 0, 0, 0]) })
}

// ---- sessions and terminals ----

#[unsafe(no_mangle)]
pub extern "C" fn getsid(pid: pid_t) -> pid_t {
    ret_int(unsafe { sys::syscall(nr::GETSID, [pid as usize, 0, 0, 0, 0, 0]) })
}

#[unsafe(no_mangle)]
pub extern "C" fn getpgid(pid: pid_t) -> pid_t {
    ret_int(sys::getpgid(pid))
}

#[unsafe(no_mangle)]
pub extern "C" fn setsid() -> pid_t {
    ret_int(sys::setsid())
}

#[unsafe(no_mangle)]
pub extern "C" fn killpg(pgrp: pid_t, sig: c_int) -> c_int {
    if pgrp < 0 {
        return ret_int(Err(sys::EINVAL));
    }
    ret_int(sys::kill(-pgrp, sig as usize))
}

const TIOCGPGRP: usize = 0x540f;
const TIOCSWINSZ: usize = 0x5414;
const TIOCGPTN: usize = 0x8004_5430;
const TIOCSPTLCK: usize = 0x4004_5431;

#[unsafe(no_mangle)]
pub extern "C" fn tcgetpgrp(fd: c_int) -> pid_t {
    let mut pgrp: pid_t = 0;
    match unsafe { sys::ioctl(fd, TIOCGPGRP, (&raw mut pgrp) as usize) } {
        Ok(_) => pgrp,
        Err(e) => ret_int(Err(e)),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ttyname_r(fd: c_int, buf: *mut c_char, len: size_t) -> c_int {
    if isatty(fd) == 0 {
        return unsafe { *errno::location() };
    }
    if len == 0 {
        return sys::ERANGE;
    }
    let out = unsafe { core::slice::from_raw_parts_mut(buf.cast::<u8>(), len) };
    match fd_path(fd, &mut out[..len - 1]) {
        Ok(n) => {
            out[n] = 0;
            0
        }
        Err(e) => e,
    }
}

/// The kernel's (and musl's) `struct termios`.
#[repr(C)]
pub struct termios {
    c_iflag: u32,
    c_oflag: u32,
    c_cflag: u32,
    c_lflag: u32,
    c_line: u8,
    c_cc: [u8; 32],
    c_ispeed: u32,
    c_ospeed: u32,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cfmakeraw(t: *mut termios) {
    let t = unsafe { &mut *t };
    // IGNBRK BRKINT PARMRK ISTRIP INLCR IGNCR ICRNL IXON
    t.c_iflag &= !(0x1 | 0x2 | 0x8 | 0x20 | 0x40 | 0x80 | 0x100 | 0x400);
    // OPOST
    t.c_oflag &= !0x1;
    // ECHO ECHONL ICANON ISIG IEXTEN
    t.c_lflag &= !(0x8 | 0x40 | 0x2 | 0x1 | 0x8000);
    // CSIZE PARENB, then CS8
    t.c_cflag = (t.c_cflag & !(0x30 | 0x100)) | 0x30;
    // VMIN, VTIME
    t.c_cc[6] = 1;
    t.c_cc[5] = 0;
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn openpty(
    master: *mut c_int,
    slave: *mut c_int,
    name: *mut c_char,
    t: *const termios,
    ws: *const c_void,
) -> c_int {
    let rw = sys::O_RDWR | sys::O_NOCTTY;
    let m = match unsafe { sys::openat(AT_FDCWD, c"/dev/ptmx".as_ptr().cast(), rw | sys::O_CLOEXEC, 0) } {
        Ok(fd) => fd,
        Err(e) => return ret_int(Err(e)),
    };
    let fail = |e| {
        let _ = sys::close(m);
        ret_int(Err(e))
    };
    let (mut unlock, mut n) = (0 as c_int, 0 as c_uint);
    if let Err(e) = unsafe { sys::ioctl(m, TIOCSPTLCK, (&raw mut unlock) as usize) } {
        return fail(e);
    }
    if let Err(e) = unsafe { sys::ioctl(m, TIOCGPTN, (&raw mut n) as usize) } {
        return fail(e);
    }
    let mut path = [0u8; 32];
    let mut b = Buf { p: path.as_mut_ptr(), left: path.len() };
    let mut digits = [0u8; 10];
    let mut i = digits.len();
    loop {
        i -= 1;
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let _ = b.take(9).map(|p| unsafe { core::ptr::copy_nonoverlapping(b"/dev/pts/".as_ptr(), p, 9) });
    let _ = b.str(&digits[i..]);
    let s = match unsafe { sys::openat(AT_FDCWD, path.as_ptr(), rw, 0) } {
        Ok(fd) => fd,
        Err(e) => return fail(e),
    };
    unsafe {
        if !t.is_null() {
            let _ = sys::ioctl(s, TCGETS + 1, t as usize);
        }
        if !ws.is_null() {
            let _ = sys::ioctl(s, TIOCSWINSZ, ws as usize);
        }
        if !name.is_null() {
            strcpy(name, path.as_ptr().cast());
        }
        *master = m;
        *slave = s;
    }
    0
}

// ---- time ----

#[unsafe(no_mangle)]
pub unsafe extern "C" fn time(t: *mut i64) -> i64 {
    let now = sys::clock_gettime(sys::CLOCK_REALTIME).sec;
    if !t.is_null() {
        unsafe { *t = now };
    }
    now
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn gettimeofday(tv: *mut timeval, _tz: *mut c_void) -> c_int {
    if !tv.is_null() {
        let now = sys::clock_gettime(sys::CLOCK_REALTIME);
        unsafe { tv.write(timeval { tv_sec: now.sec, tv_usec: now.nsec / 1000 }) };
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn sleep(secs: c_uint) -> c_uint {
    let _ = sys::nanosleep(&sys::Timespec { sec: secs as i64, nsec: 0 });
    0
}

/// On `pselect6`; the timeout is updated with the time left, as Linux's
/// `select` does.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn select(n: c_int, r: *mut c_void, w: *mut c_void, e: *mut c_void, tv: *mut timeval) -> c_int {
    let mut ts = (!tv.is_null()).then(|| unsafe { sys::Timespec { sec: (*tv).tv_sec, nsec: (*tv).tv_usec * 1000 } });
    let tsp = ts.as_mut().map_or(core::ptr::null_mut(), |t| t as *mut sys::Timespec);
    let res = unsafe { sys::syscall(nr::PSELECT6, [n as usize, r as usize, w as usize, e as usize, tsp as usize, 0]) };
    if let Some(t) = ts {
        unsafe { tv.write(timeval { tv_sec: t.sec, tv_usec: t.nsec / 1000 }) };
    }
    ret_int(res)
}

// ---- groups ----

/// The groups `user` is a member of in /etc/group, with `group` first.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getgrouplist(user: *const c_char, group: gid_t, groups: *mut gid_t, ngroups: *mut c_int) -> c_int {
    let user = unsafe { CStr::from_ptr(user) }.to_bytes();
    let max = unsafe { *ngroups }.max(0) as usize;
    let mut n = 0;
    let mut add = |g: gid_t| {
        let have = unsafe { core::slice::from_raw_parts(groups, n.min(max)) };
        if !have.contains(&g) {
            if n < max {
                unsafe { *groups.add(n) = g };
            }
            n += 1;
        }
    };
    add(group);
    let _ = with_file(c"/etc/group", |f| {
        for line in f.split(|&b| b == b'\n') {
            let mut fields = line.split(|&b| b == b':');
            let (Some(_), Some(_), Some(gid), Some(members)) = (fields.next(), fields.next(), fields.next(), fields.next()) else {
                continue;
            };
            if members.split(|&b| b == b',').any(|m| m == user) {
                if let Some(g) = parse_id(gid) {
                    add(g);
                }
            }
        }
    });
    unsafe { *ngroups = n as c_int };
    if n > max { -1 } else { n as c_int }
}

// ---- the C locale ----

/// The one locale: every `newlocale` is the C locale, with UTF-8 text.
static C_LOCALE: u8 = 0;

#[unsafe(no_mangle)]
pub extern "C" fn newlocale(_mask: c_int, _name: *const c_char, _base: *mut c_void) -> *mut c_void {
    (&raw const C_LOCALE).cast_mut().cast()
}

#[unsafe(no_mangle)]
pub extern "C" fn freelocale(_l: *mut c_void) {}

#[unsafe(no_mangle)]
pub extern "C" fn uselocale(_l: *mut c_void) -> *mut c_void {
    newlocale(0, core::ptr::null(), core::ptr::null_mut())
}

/// The C locale's `nl_langinfo` items, as glibc and musl number them.
#[unsafe(no_mangle)]
pub extern "C" fn nl_langinfo(item: c_int) -> *mut c_char {
    const DAYS: [&CStr; 7] = [c"Sunday", c"Monday", c"Tuesday", c"Wednesday", c"Thursday", c"Friday", c"Saturday"];
    const ABDAYS: [&CStr; 7] = [c"Sun", c"Mon", c"Tue", c"Wed", c"Thu", c"Fri", c"Sat"];
    const MONTHS: [&CStr; 12] = [
        c"January", c"February", c"March", c"April", c"May", c"June", c"July", c"August", c"September", c"October",
        c"November", c"December",
    ];
    const ABMONTHS: [&CStr; 12] =
        [c"Jan", c"Feb", c"Mar", c"Apr", c"May", c"Jun", c"Jul", c"Aug", c"Sep", c"Oct", c"Nov", c"Dec"];
    let s: &CStr = match item {
        14 => c"UTF-8",
        0x10000 => c".",
        0x20000..=0x20006 => ABDAYS[(item - 0x20000) as usize],
        0x20007..=0x2000d => DAYS[(item - 0x20007) as usize],
        0x2000e..=0x20019 => ABMONTHS[(item - 0x2000e) as usize],
        0x2001a..=0x20025 => MONTHS[(item - 0x2001a) as usize],
        0x20026 => c"AM",
        0x20027 => c"PM",
        0x20028 => c"%a %b %e %H:%M:%S %Y",
        0x20029 => c"%m/%d/%y",
        0x2002a => c"%H:%M:%S",
        0x2002b => c"%I:%M:%S %p",
        0x50000 => c"^[yY]",
        0x50001 => c"^[nN]",
        _ => c"",
    };
    s.as_ptr().cast_mut()
}

#[unsafe(no_mangle)]
pub extern "C" fn nl_langinfo_l(item: c_int, _l: *mut c_void) -> *mut c_char {
    nl_langinfo(item)
}

/// iconv between UTF-8 and itself (the C locale's codeset here): a copy.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iconv_open(to: *const c_char, from: *const c_char) -> *mut c_void {
    let utf8 = |s: *const c_char| {
        let s = unsafe { CStr::from_ptr(s) }.to_bytes();
        let s = s.split(|&b| b == b'/').next().unwrap_or(s);
        s.eq_ignore_ascii_case(b"UTF-8") || s.eq_ignore_ascii_case(b"UTF8")
    };
    if utf8(to) && utf8(from) {
        return core::ptr::without_provenance_mut(1);
    }
    set_errno(sys::EINVAL);
    core::ptr::without_provenance_mut(usize::MAX)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn iconv(
    _cd: *mut c_void,
    inbuf: *mut *mut c_char,
    inleft: *mut size_t,
    outbuf: *mut *mut c_char,
    outleft: *mut size_t,
) -> size_t {
    if inbuf.is_null() || unsafe { (*inbuf).is_null() } {
        return 0;
    }
    unsafe {
        let n = (*inleft).min(*outleft);
        core::ptr::copy_nonoverlapping(*inbuf, *outbuf, n);
        *inbuf = (*inbuf).add(n);
        *outbuf = (*outbuf).add(n);
        *inleft -= n;
        *outleft -= n;
        if *inleft > 0 {
            set_errno(sys::E2BIG);
            return usize::MAX;
        }
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn iconv_close(_cd: *mut c_void) -> c_int {
    0
}

// ---- the environment, for C code that reads `environ` ----

/// The initial environment, set at startup.
#[unsafe(no_mangle)]
pub static mut environ: *mut *mut c_char = core::ptr::null_mut();

#[unsafe(no_mangle)]
pub unsafe extern "C" fn nanosleep(req: *const sys::Timespec, rem: *mut sys::Timespec) -> c_int {
    // CLOCK_REALTIME, relative; the time left in `rem` when interrupted
    ret_int(unsafe { sys::clock_nanosleep(sys::CLOCK_REALTIME, 0, req, rem) })
}
