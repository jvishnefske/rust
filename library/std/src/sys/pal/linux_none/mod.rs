//! Linux without libc (`*-unknown-linux-none`): std on raw syscalls.
//!
//! `linux_none_rt` is the C runtime here: it defines `_start`, which records
//! the arguments, sets up the main thread's TLS and calls the C `main` rustc
//! generates (and so `lang_start`, which calls [`init`]). It also provides the
//! syscall wrappers, threads, process spawning and the allocator that the
//! `linux_none` arms of the `sys` modules are built on.
//!
//! The `libc` crate is still a dependency, for the types and constants that
//! `os::unix` and `os::linux` expose (it gives linux-none musl's, which match
//! the kernel's), but no libc function is called.

#![allow(missing_docs, nonstandard_style)]
#![forbid(unsafe_op_in_unsafe_fn)]

use linux_none_rt::sys;

use crate::io;
use crate::sync::atomic::{AtomicBool, Ordering};

pub mod futex;
pub mod stack_overflow;
#[path = "../unix/time.rs"]
pub mod time;

static ON_BROKEN_PIPE_USED: AtomicBool = AtomicBool::new(false);

// SAFETY: must be called only once during runtime initialization.
pub unsafe fn init(argc: isize, argv: *const *const u8, sigpipe: u8) {
    sanitize_standard_fds();
    reset_sigpipe(sigpipe);
    unsafe { stack_overflow::init() };
    unsafe { crate::sys::args::init(argc, argv) };
    // libc's `exit` runs the exiting thread's TLS destructors: so does ours
    linux_none_rt::start::set_exit_hook(run_thread_exit);
}

/// Make sure fds 0, 1 and 2 are open, so that files opened later never end
/// up as stdio by accident.
fn sanitize_standard_fds() {
    for fd in 0..3 {
        if let Err(sys::EBADF) = sys::fcntl(fd, sys::F_GETFD, 0) {
            let r = unsafe { sys::openat(sys::AT_FDCWD, c"/dev/null".as_ptr().cast(), sys::O_RDWR, 0) };
            if r.is_err() {
                abort_internal();
            }
        }
    }
}

fn reset_sigpipe(sigpipe: u8) {
    mod sigpipe {
        pub const DEFAULT: u8 = 0;
        pub const INHERIT: u8 = 1;
        pub const SIG_IGN: u8 = 2;
        pub const SIG_DFL: u8 = 3;
    }
    let (used, handler) = match sigpipe {
        sigpipe::DEFAULT => (false, Some(sys::SIG_IGN)),
        sigpipe::INHERIT => (true, None),
        sigpipe::SIG_IGN => (true, Some(sys::SIG_IGN)),
        sigpipe::SIG_DFL => (true, Some(sys::SIG_DFL)),
        _ => unreachable!(),
    };
    if used {
        ON_BROKEN_PIPE_USED.store(true, Ordering::Relaxed);
    }
    if let Some(handler) = handler {
        let act = linux_none_rt::arch::KSigaction { handler, flags: 0, restorer: 0, mask: 0 };
        if unsafe { sys::rt_sigaction(sys::SIGPIPE, &act, crate::ptr::null_mut()) }.is_err() {
            rtabort!("failed to set the SIGPIPE disposition");
        }
    }
}

pub(crate) fn on_broken_pipe_used() -> bool {
    ON_BROKEN_PIPE_USED.load(Ordering::Relaxed)
}

/// What a thread does on its way out: run its TLS destructors, then std's
/// per-thread cleanup. Spawned threads call it after their main function;
/// `linux_none_rt::start::exit` calls it for the thread that exits the
/// process.
pub(crate) fn run_thread_exit() {
    unsafe { crate::sys::thread_local::destructors::run() };
    crate::rt::thread_cleanup();
}

// SAFETY: must be called only once during runtime cleanup.
pub unsafe fn cleanup() {}

/// Converts the `Err(errno)` of a syscall wrapper to an `io::Error` (and
/// records the errno for `io::Error::last_os_error`).
#[inline]
pub fn cvt<T>(r: Result<T, i32>) -> io::Result<T> {
    r.map_err(|e| {
        crate::sys::io::set_errno(e);
        io::Error::from_raw_os_error(e)
    })
}

/// [`cvt`], retrying while the call fails with `EINTR`.
pub fn cvt_r<T>(mut f: impl FnMut() -> Result<T, i32>) -> io::Result<T> {
    loop {
        match f() {
            Err(sys::EINTR) => {}
            r => return cvt(r),
        }
    }
}

pub fn abort_internal() -> ! {
    linux_none_rt::start::abort()
}

pub fn unsupported<T>() -> io::Result<T> {
    Err(unsupported_err())
}

pub fn unsupported_err() -> io::Error {
    io::Error::UNSUPPORTED_PLATFORM
}
