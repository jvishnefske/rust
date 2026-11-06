//! The "has overflowed its stack" message, as `unix/stack_overflow.rs` prints
//! it: a SIGSEGV/SIGBUS handler on an alternate signal stack checks whether
//! the fault hit the thread's guard page and, if so, reports and aborts.
//!
//! - Threads spawned by `linux_none_rt` have a guard page below their stack
//!   and an alternate signal stack in their mapping; the runtime finds both
//!   from the thread pointer.
//! - The main thread's stack is the kernel's, growing down to `RLIMIT_STACK`
//!   or to the gap the kernel keeps below other mappings. It has overflowed
//!   when the fault is in the page just below its mapping in
//!   `/proc/self/maps` (looked up in the handler, so startup does not pay
//!   for it).
//!
//! Thread-locals are ELF TLS at fixed offsets from the thread pointer here,
//! allocated before the thread runs, so the handler can read them.

use linux_none_rt::{signal, sys};

use crate::cell::Cell;
use crate::ptr::NonNull;
use crate::sync::atomic::{AtomicUsize, Ordering};

/// An address on the main thread's stack (0: no handler installed).
static MAIN_STACK: AtomicUsize = AtomicUsize::new(0);

/// The thread's name, copied when it starts: the handler must not look at
/// the `Thread` handle.
#[thread_local]
static NAME: Cell<Option<NonNull<str>>> = Cell::new(None);

/// Install the handler, unless the program already set SIGSEGV or SIGBUS
/// handlers.
///
/// # Safety
/// Must be called only once, on the main thread, during startup.
pub unsafe fn init() {
    // as on unix: with panic=immediate-abort, keep the plain SIGSEGV
    if cfg!(panic = "immediate-abort") {
        return;
    }
    let mut installed = false;
    for sig in [sys::SIGSEGV, sys::SIGBUS] {
        if signal::disposition(sig) == Ok(sys::SIG_DFL) {
            // SAFETY: the handler is async-signal-safe
            installed |= unsafe { signal::set_handler(sig, signal_handler) }.is_ok();
        }
    }
    if installed {
        if signal::enable_altstacks().is_err() {
            rtabort!("failed to allocate an alternative stack");
        }
        let here = 0u8;
        MAIN_STACK.store((&raw const here).addr(), Ordering::Relaxed);
        thread_start();
    }
}

/// Record the calling thread's name for the handler.
pub fn thread_start() {
    if MAIN_STACK.load(Ordering::Relaxed) == 0 {
        return;
    }
    let name = crate::thread::with_current_name(|name| name.map(Box::<str>::from));
    NAME.set(name.map(|n| NonNull::from(Box::leak(n))));
}

/// Free what [`thread_start`] recorded.
pub fn thread_exit() {
    if let Some(name) = NAME.take() {
        // SAFETY: leaked from a box by `thread_start`
        drop(unsafe { Box::from_raw(name.as_ptr()) });
    }
}

/// The calling thread's guard page, as `(start, end)`.
fn guard_page() -> Option<(usize, usize)> {
    if let Some(guard) = linux_none_rt::thread::current_guard() {
        return Some(guard);
    }
    let (lo, _) = signal::find_mapping(MAIN_STACK.load(Ordering::Relaxed))?;
    Some((lo - sys::PAGE_SIZE, lo))
}

/// SIGSEGV and SIGBUS: report a stack overflow and abort. Anything else
/// gets the default disposition back and happens again: a fault re-executes
/// the faulting instruction on return, a signal sent with `kill` is sent
/// again (and stays pending until the handler returns).
unsafe extern "C" fn signal_handler(signum: i32, info: *mut signal::SigInfo, _ctx: *mut u8) {
    // SAFETY: the kernel passes a valid siginfo
    let (code, addr) = unsafe { ((*info).code, (*info).addr) };
    if code > 0
        && let Some((start, end)) = guard_page()
        && (start..end).contains(&addr)
    {
        // everything from here on must be async-signal-safe: the name was
        // copied beforehand, gettid is a syscall, printing is a raw write
        let tid = sys::gettid();
        // SAFETY: set by `thread_start` and only freed by this thread
        let name = NAME.get().map_or("<unknown>", |n| unsafe { n.as_ref() });
        rtprintpanic!("\nthread '{name}' ({tid}) has overflowed its stack\n");
        rtabort!("stack overflow");
    }
    let _ = signal::set_default(signum as usize);
    if code <= 0 {
        let _ = sys::tgkill(sys::getpid(), sys::gettid(), signum as usize);
    }
}
