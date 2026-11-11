//! What std's stack overflow handler needs from the runtime: `SA_SIGINFO`
//! handlers that run on an alternate signal stack, those stacks (one per
//! thread), and the main thread's stack mapping from `/proc/self/maps`.
//!
//! Spawned threads get their alternate stack inside their own mapping (see
//! [`crate::thread`]) once [`enable_altstacks`] has been called; the main
//! thread gets a separate mapping then.

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::arch::KSigaction;
use crate::sys::{self, PAGE_SIZE, SysResult};

/// The start of the kernel's `siginfo_t` (128 bytes in all), up to the
/// faulting address of SIGSEGV and SIGBUS.
#[repr(C)]
pub struct SigInfo {
    pub signo: i32,
    pub errno: i32,
    /// `> 0` when the kernel raised the signal (a fault), `<= 0` when it was
    /// sent (`kill`, `tgkill`, `sigqueue`)
    pub code: i32,
    _pad: i32,
    pub addr: usize,
}

/// An `SA_SIGINFO` handler: `(signo, info, ucontext)`.
pub type Handler = unsafe extern "C" fn(i32, *mut SigInfo, *mut u8);

/// The current disposition of `sig` (`SIG_DFL`, `SIG_IGN` or a handler).
pub fn disposition(sig: usize) -> SysResult<usize> {
    let mut old = KSigaction { handler: 0, flags: 0, restorer: 0, mask: 0 };
    unsafe { sys::rt_sigaction(sig, core::ptr::null(), &mut old)? };
    Ok(old.handler)
}

/// Install `handler` for `sig`, to run on the alternate signal stack with
/// `sig` blocked.
///
/// # Safety
/// `handler` must be safe to run whenever `sig` is delivered.
pub unsafe fn set_handler(sig: usize, handler: Handler) -> SysResult {
    let act = KSigaction {
        handler: handler as usize,
        flags: sys::SA_SIGINFO | sys::SA_ONSTACK | sys::SA_RESTORER,
        restorer: crate::arch::restore_rt as unsafe extern "C" fn() -> ! as usize,
        mask: 0,
    };
    unsafe { sys::rt_sigaction(sig, &act, core::ptr::null_mut()) }
}

/// Give `sig` its default disposition back.
pub fn set_default(sig: usize) -> SysResult {
    let act = KSigaction { handler: sys::SIG_DFL, flags: 0, restorer: 0, mask: 0 };
    unsafe { sys::rt_sigaction(sig, &act, core::ptr::null_mut()) }
}

const AT_MINSIGSTKSZ: usize = 51;

/// The size of each thread's alternate signal stack, 0 until
/// [`enable_altstacks`].
static ALTSTACK_SIZE: AtomicUsize = AtomicUsize::new(0);

/// Room for the kernel's signal frame (`AT_MINSIGSTKSZ`, which grows with
/// the CPU's register state) and for the handler itself, which formats a
/// message and reads `/proc/self/maps`.
fn altstack_size() -> usize {
    let frame = crate::start::auxv(AT_MINSIGSTKSZ).unwrap_or(0).max(16 * 1024);
    (frame + 48 * 1024).next_multiple_of(PAGE_SIZE)
}

/// Give the calling (main) thread an alternate signal stack, and every
/// thread spawned from now on its own.
pub fn enable_altstacks() -> SysResult {
    let size = altstack_size();
    // a guard page below it, like any stack
    let base = unsafe {
        sys::mmap(
            0,
            PAGE_SIZE + size,
            sys::PROT_READ | sys::PROT_WRITE,
            sys::MAP_PRIVATE | sys::MAP_ANONYMOUS | sys::MAP_STACK,
            -1,
            0,
        )?
    };
    let _ = unsafe { sys::mprotect(base, PAGE_SIZE, sys::PROT_NONE) };
    unsafe { set_altstack(base + PAGE_SIZE, size)? };
    ALTSTACK_SIZE.store(size, Ordering::Relaxed);
    Ok(0)
}

/// The alternate signal stack size for new threads (0: none).
pub(crate) fn thread_altstack_size() -> usize {
    ALTSTACK_SIZE.load(Ordering::Relaxed)
}

/// Make `[sp, sp + size)` the calling thread's alternate signal stack.
pub(crate) unsafe fn set_altstack(sp: usize, size: usize) -> SysResult {
    let ss = sys::StackT { sp, flags: 0, size };
    unsafe { sys::sigaltstack(&ss, core::ptr::null_mut()) }
}

/// Stop using the calling thread's alternate signal stack (before it is
/// unmapped).
pub(crate) fn disable_altstack() {
    let ss = sys::StackT { sp: 0, flags: sys::SS_DISABLE, size: 0 };
    let _ = unsafe { sys::sigaltstack(&ss, core::ptr::null_mut()) };
}

/// The mapping in `/proc/self/maps` that contains `addr`, as `(start, end)`.
///
/// Async-signal-safe: raw syscalls and a buffer on the stack, nothing else.
pub fn find_mapping(addr: usize) -> Option<(usize, usize)> {
    let fd = unsafe { sys::openat(sys::AT_FDCWD, c"/proc/self/maps".as_ptr().cast(), sys::O_RDONLY | sys::O_CLOEXEC, 0) }.ok()?;
    let mut buf = [0u8; 512];
    let mut parser = MapsParser::new();
    let mut found = None;
    'read: loop {
        let n = match unsafe { sys::read(fd, buf.as_mut_ptr(), buf.len()) } {
            Ok(0) => break,
            Ok(n) => n,
            Err(sys::EINTR) => continue,
            Err(_) => break,
        };
        for &b in &buf[..n] {
            if let Some((lo, hi)) = parser.feed(b)
                && (lo..hi).contains(&addr)
            {
                found = Some((lo, hi));
                break 'read;
            }
        }
    }
    let _ = sys::close(fd);
    found
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Start,
    Hi,
    Rest,
}

/// Reads the `start-end ` at the front of each line of `/proc/self/maps`
/// (lowercase hex), one byte at a time so that no line has to fit a buffer.
pub struct MapsParser {
    state: State,
    lo: usize,
    hi: usize,
    digits: u32,
}

impl MapsParser {
    pub const fn new() -> MapsParser {
        MapsParser { state: State::Start, lo: 0, hi: 0, digits: 0 }
    }

    /// Feed the next byte; returns a line's range once its end address is
    /// complete. A malformed line yields nothing.
    pub fn feed(&mut self, b: u8) -> Option<(usize, usize)> {
        if b == b'\n' {
            *self = MapsParser::new();
            return None;
        }
        let digit = match b {
            b'0'..=b'9' => Some((b - b'0') as usize),
            b'a'..=b'f' => Some((b - b'a' + 10) as usize),
            _ => None,
        };
        match (self.state, digit, b) {
            (State::Rest, _, _) => {}
            (State::Start | State::Hi, Some(d), _) => {
                if self.digits as usize >= 2 * size_of::<usize>() {
                    self.state = State::Rest;
                    return None;
                }
                self.digits += 1;
                let v = if self.state == State::Start { &mut self.lo } else { &mut self.hi };
                *v = (*v << 4) | d;
            }
            (State::Start, None, b'-') if self.digits > 0 => {
                self.state = State::Hi;
                self.digits = 0;
            }
            (State::Hi, None, b' ') if self.digits > 0 => {
                self.state = State::Rest;
                return Some((self.lo, self.hi));
            }
            _ => self.state = State::Rest,
        }
        None
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Any input is safe to feed (no overflow or panic), and a well-formed
    /// line prefix yields exactly its two addresses.
    #[kani::proof]
    #[kani::unwind(12)]
    fn maps_parser() {
        let junk: [u8; 10] = kani::any();
        let mut p = MapsParser::new();
        for b in junk {
            let _ = p.feed(b);
        }

        let lo: u8 = kani::any();
        let hi: u8 = kani::any();
        let hex = |n: u8| if n < 10 { b'0' + n } else { b'a' + n - 10 };
        let line = [b'\n', hex(lo >> 4), hex(lo & 15), b'-', hex(hi >> 4), hex(hi & 15), b' ', b'r'];
        let mut got = None;
        for b in line {
            if let Some(r) = p.feed(b) {
                assert!(got.is_none());
                got = Some(r);
            }
        }
        assert!(got == Some((lo as usize, hi as usize)));
    }

    /// Sixteen hex digits fill a usize; a seventeenth makes the line malformed.
    #[kani::proof]
    #[kani::unwind(20)]
    fn maps_parser_width() {
        let n: usize = kani::any_where(|&n| n <= 17);
        let mut p = MapsParser::new();
        for _ in 0..n {
            let _ = p.feed(b'f');
        }
        let _ = p.feed(b'-');
        let _ = p.feed(b'1');
        let r = p.feed(b' ');
        assert!(r.is_some() == (1..=16).contains(&n));
        if let Some((lo, _)) = r {
            assert!(lo == usize::MAX >> (64 - 4 * n));
        }
    }
}
