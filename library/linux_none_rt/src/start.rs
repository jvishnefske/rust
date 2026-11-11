//! Process entry and exit: what crt1.o and libc's `exit` do elsewhere.
//!
//! On linux-none the kernel enters at `_start` ([`crate::arch`]), which calls
//! [`start`] with the initial stack pointer. `start` records argc/argv/envp/
//! auxv, resolves the vDSO, sets up the main thread's TLS, runs
//! `.init_array`, and calls the C `main` that rustc generates for a binary
//! (which runs std's `lang_start`).

use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use crate::sys;

static ARGC: AtomicUsize = AtomicUsize::new(0);
static ARGV: AtomicPtr<*const u8> = AtomicPtr::new(core::ptr::null_mut());
static ENVP: AtomicPtr<*const u8> = AtomicPtr::new(core::ptr::null_mut());
static AUXV: AtomicPtr<usize> = AtomicPtr::new(core::ptr::null_mut());
static EXIT_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

pub const AT_PHDR: usize = 3;
pub const AT_PHNUM: usize = 5;
pub const AT_PAGESZ: usize = 6;
pub const AT_HWCAP: usize = 16;
pub const AT_RANDOM: usize = 25;
pub const AT_HWCAP2: usize = 26;
pub const AT_EXECFN: usize = 31;

/// Called from `_start` with the initial stack pointer, where the kernel left
/// `argc, argv[], NULL, envp[], NULL, auxv[]`.
#[cfg(linux_none)]
pub(crate) unsafe extern "C" fn start(sp: *const usize) -> ! {
    unsafe extern "C" {
        fn main(argc: i32, argv: *const *const u8) -> i32;
    }
    unsafe {
        init(sp);
        crate::vdso::init();
        crate::tls::init_main_thread();
        run_init_array();
        let code = main(ARGC.load(Ordering::Relaxed) as i32, ARGV.load(Ordering::Relaxed));
        exit(code)
    }
}

/// Record the process arguments from the initial stack.
///
/// # Safety
/// `sp` must be the initial stack pointer the kernel passed to the entry point.
pub unsafe fn init(sp: *const usize) {
    unsafe {
        let argc = *sp;
        let argv = sp.add(1) as *mut *const u8;
        ARGC.store(argc, Ordering::Relaxed);
        ARGV.store(argv, Ordering::Relaxed);
        let envp = argv.add(argc + 1);
        ENVP.store(envp, Ordering::Relaxed);
        #[cfg(linux_none)]
        {
            crate::clib::environ = envp.cast();
        }
        let mut p = envp;
        while !(*p).is_null() {
            p = p.add(1);
        }
        AUXV.store(p.add(1) as *mut usize, Ordering::Relaxed);
    }
}

/// Run static constructors (`.init_array`), as crt startup code would.
#[cfg(linux_none)]
unsafe fn run_init_array() {
    unsafe extern "C" {
        static __init_array_start: [unsafe extern "C" fn(); 0];
        static __init_array_end: [unsafe extern "C" fn(); 0];
    }
    unsafe {
        let mut f = &raw const __init_array_start as *const unsafe extern "C" fn();
        let end = &raw const __init_array_end as *const unsafe extern "C" fn();
        while f < end {
            (*f)();
            f = f.add(1);
        }
    }
}

/// `argc` and `argv` as the kernel passed them (`argv[argc]` is null).
pub fn args() -> (usize, *const *const u8) {
    (ARGC.load(Ordering::Relaxed), ARGV.load(Ordering::Relaxed))
}

/// The initial environment, a null-terminated array of `KEY=VALUE` strings
/// (null before [`init`]).
pub fn envp() -> *const *const u8 {
    ENVP.load(Ordering::Relaxed)
}

/// Look up an entry of the ELF auxiliary vector.
pub fn auxv(key: usize) -> Option<usize> {
    let mut p = AUXV.load(Ordering::Relaxed) as *const usize;
    if p.is_null() {
        return None;
    }
    unsafe {
        while *p != 0 {
            if *p == key {
                return Some(*p.add(1));
            }
            p = p.add(2);
        }
    }
    None
}

/// libc's `getauxval`, which compiler-builtins calls on aarch64 (and C
/// code in crates, such as aws-lc, everywhere).
#[cfg(all(linux_none, not(kani)))]
#[unsafe(no_mangle)]
extern "C" fn getauxval(key: core::ffi::c_ulong) -> core::ffi::c_ulong {
    auxv(key as usize).unwrap_or(0) as core::ffi::c_ulong
}

/// Set the function [`exit`] calls before terminating the process (std runs
/// the exiting thread's TLS destructors there, as libc's `exit` does).
pub fn set_exit_hook(f: fn()) {
    EXIT_HOOK.store(f as *mut (), Ordering::Release);
}

/// Run the exit hook, then terminate the process.
pub fn exit(code: i32) -> ! {
    let hook = EXIT_HOOK.swap(core::ptr::null_mut(), Ordering::Acquire);
    if !hook.is_null() {
        let f: fn() = unsafe { core::mem::transmute(hook) };
        f();
    }
    sys::exit_group(code)
}

/// Raise SIGABRT with the default disposition, as libc's `abort` does.
pub fn abort() -> ! {
    unsafe {
        let act = crate::arch::KSigaction { handler: sys::SIG_DFL, flags: 0, restorer: 0, mask: 0 };
        let _ = sys::rt_sigaction(sys::SIGABRT, &act, core::ptr::null_mut());
        let set: u64 = 1 << (sys::SIGABRT - 1);
        let _ = sys::rt_sigprocmask(sys::SIG_UNBLOCK, &set, core::ptr::null_mut());
    }
    let _ = sys::tgkill(sys::getpid(), sys::gettid(), sys::SIGABRT);
    sys::exit_group(134)
}

/// Write all of `s` to stderr, ignoring errors (for messages on the way to
/// an abort).
pub fn write_stderr(s: &[u8]) {
    sys::write_all_raw(2, s)
}
