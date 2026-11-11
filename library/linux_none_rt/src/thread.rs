//! Native threads created with `clone(2)`.
//!
//! One anonymous mapping per thread holds, from the bottom: a guard page, the
//! stack, the thread's TLS area and its [`Control`] block. Once
//! [`signal::enable_altstacks`] has been called, an alternate signal stack
//! with its own guard page goes below all that. The kernel clears
//! `Control::tid` and wakes it as a futex when the thread exits
//! (`CLONE_CHILD_CLEARTID`), which is what [`Thread::join`] waits for. A
//! detached thread unmaps its own mapping on the way out.
//!
//! The TLS area's TCB points back at the [`Control`] block, so a thread can
//! find its own guard page ([`current_guard`]), even in a signal handler.

use core::mem::size_of;
use core::sync::atomic::{AtomicU32, AtomicUsize};
use core::sync::atomic::Ordering::{AcqRel, Acquire, Release};

use crate::sys::{self, PAGE_SIZE};
use crate::{arch, futex, signal, tls};

const RUNNING: u32 = 0;
const DETACHED: u32 = 1;
const FINISHED: u32 = 2;

/// The smallest stack [`spawn`] hands out.
pub const MIN_STACK: usize = 64 * 1024;

#[repr(C)]
struct Control {
    tid: AtomicU32,
    state: AtomicU32,
    map_base: usize,
    map_len: usize,
    /// the stack's guard page, and the top of the stack above it
    guard: usize,
    stack_top: usize,
    /// alternate signal stack size (0: none), at `map_base + PAGE_SIZE`
    altstack: usize,
    entry: unsafe fn(*mut u8),
    arg: *mut u8,
}

/// A spawned thread: [`join`](Thread::join) or [`detach`](Thread::detach) it
/// exactly once (dropping it leaks the thread's mapping).
pub struct Thread {
    ctl: *mut Control,
}

unsafe impl Send for Thread {}
unsafe impl Sync for Thread {}

const fn round_up(n: usize, to: usize) -> usize {
    (n + to - 1) & !(to - 1)
}

/// Start a thread running `entry(arg)` on a stack of at least `stack_size`
/// bytes. `entry` must return normally; the thread then exits.
///
/// # Safety
/// `entry` must be safe to call with `arg` on the new thread.
pub unsafe fn spawn(stack_size: usize, entry: unsafe fn(*mut u8), arg: *mut u8) -> Result<Thread, i32> {
    let stack_size = round_up(stack_size.max(MIN_STACK), PAGE_SIZE);
    let tls_len = tls::Layout::new(&tls::image()).reserve();
    let top_len = round_up(tls_len + size_of::<Control>() + 64, PAGE_SIZE);
    let altstack = signal::thread_altstack_size();
    let alt_len = if altstack > 0 { PAGE_SIZE + altstack } else { 0 };
    let map_len = alt_len + PAGE_SIZE + stack_size + top_len;
    let base = unsafe {
        sys::mmap(
            0,
            map_len,
            sys::PROT_READ | sys::PROT_WRITE,
            sys::MAP_PRIVATE | sys::MAP_ANONYMOUS | sys::MAP_STACK,
            -1,
            0,
        )?
    };
    // guard pages below the stack and the alternate signal stack
    let guard = base + alt_len;
    let _ = unsafe { sys::mprotect(guard, PAGE_SIZE, sys::PROT_NONE) };
    if altstack > 0 {
        let _ = unsafe { sys::mprotect(base, PAGE_SIZE, sys::PROT_NONE) };
    }

    let ctl_addr = (base + map_len - size_of::<Control>()) & !63;
    let ctl = ctl_addr as *mut Control;
    let top = guard + PAGE_SIZE + stack_size;
    let tp = unsafe {
        ctl.write(Control {
            tid: AtomicU32::new(0),
            state: AtomicU32::new(RUNNING),
            map_base: base,
            map_len,
            guard,
            stack_top: top,
            altstack,
            entry,
            arg,
        });
        let tp = tls::init_area(top as *mut u8);
        tls::set_thread_word(tp, ctl_addr);
        tp
    };

    // the trampoline pops `thread_start` then `ctl` off the new stack
    let sp = ((top & !15) - 16) as *mut usize;
    unsafe {
        *sp = thread_start as extern "C" fn(*mut u8) -> ! as usize;
        *sp.add(1) = ctl_addr;
    }

    let flags = sys::CLONE_VM
        | sys::CLONE_FS
        | sys::CLONE_FILES
        | sys::CLONE_SIGHAND
        | sys::CLONE_THREAD
        | sys::CLONE_SYSVSEM
        | sys::CLONE_SETTLS
        | sys::CLONE_PARENT_SETTID
        | sys::CLONE_CHILD_CLEARTID;
    let tid = unsafe { (*ctl).tid.as_ptr() };
    let r = unsafe { arch::clone_thread(flags, sp, tid, tid, tp) };
    if r < 0 {
        let _ = unsafe { sys::munmap(base, map_len) };
        return Err(-r as i32);
    }
    Ok(Thread { ctl })
}

extern "C" fn thread_start(arg: *mut u8) -> ! {
    let ctl = arg as *mut Control;
    unsafe {
        if (*ctl).altstack > 0 {
            let _ = signal::set_altstack((*ctl).map_base + PAGE_SIZE, (*ctl).altstack);
        }
        ((*ctl).entry)((*ctl).arg);
        let hook = EXIT_HOOK.load(Acquire);
        if hook != 0 {
            core::mem::transmute::<usize, fn()>(hook)();
        }
        if (*ctl).altstack > 0 {
            signal::disable_altstack();
        }
        let (base, len) = ((*ctl).map_base, (*ctl).map_len);
        if (*ctl).state.swap(FINISHED, AcqRel) == DETACHED {
            // Nobody will join us: free our own mapping on the way out. Our
            // clear-tid word lives in it, so unregister that first; otherwise
            // the kernel's write of 0 at exit could land in memory another
            // thread has since mapped at the same address.
            let _ = sys::set_tid_address(core::ptr::null_mut());
            arch::unmap_stack_and_exit(base, len);
        }
        sys::exit_thread(0)
    }
}

/// Run on each spawned thread as it finishes (not on the main thread): the
/// C library's `pthread_key_create` destructors.
static EXIT_HOOK: AtomicUsize = AtomicUsize::new(0);

pub fn set_exit_hook(f: fn()) {
    EXIT_HOOK.store(f as usize, Release);
}

/// The calling thread's stack, as `(lowest, top)`; None on the main thread.
#[cfg(linux_none)]
pub fn current_stack() -> Option<(usize, usize)> {
    let ctl = tls::thread_word() as *const Control;
    if ctl.is_null() {
        return None;
    }
    let ctl = unsafe { &*ctl };
    Some((ctl.guard + PAGE_SIZE, ctl.stack_top))
}

/// The calling thread's stack guard page, as `(start, end)`; None on the
/// main thread, whose stack the kernel manages. Async-signal-safe.
#[cfg(linux_none)]
pub fn current_guard() -> Option<(usize, usize)> {
    let ctl = tls::thread_word() as *const Control;
    if ctl.is_null() {
        return None;
    }
    let guard = unsafe { (*ctl).guard };
    Some((guard, guard + PAGE_SIZE))
}

impl Thread {
    /// The address of the thread's control block: an id that is unique
    /// among live threads and does not change.
    pub fn as_raw(&self) -> usize {
        self.ctl as usize
    }

    /// The kernel thread id (0 once the thread has exited).
    pub fn tid(&self) -> u32 {
        unsafe { (*self.ctl).tid.load(Acquire) }
    }

    /// Wait for the thread to exit, then free its mapping.
    pub fn join(self) {
        let ctl = unsafe { &*self.ctl };
        loop {
            let t = ctl.tid.load(Acquire);
            if t == 0 {
                break;
            }
            futex::wait_shared(&ctl.tid, t);
        }
        let (base, len) = (ctl.map_base, ctl.map_len);
        let _ = unsafe { sys::munmap(base, len) };
    }

    /// Let the thread free its own mapping when it finishes.
    pub fn detach(self) {
        let ctl = unsafe { &*self.ctl };
        if ctl.state.swap(DETACHED, AcqRel) == FINISHED {
            // it already finished and will not free its mapping itself
            self.join();
        }
    }
}
