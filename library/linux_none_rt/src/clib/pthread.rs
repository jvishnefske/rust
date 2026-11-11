//! The pthread functions C code and crates call, on the runtime's threads
//! (which are not pthreads: there is no `pthread_create`). Thread-specific
//! keys, reader-writer locks, `pthread_self`, the calling thread's stack
//! bounds, and fork handlers. The types are musl's sizes.

use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use super::size_t;
use crate::locks::{RawMutex, RawRwLock};
use crate::sys;

type pthread_t = usize;
type pthread_key_t = u32;

// ---- keys ----

const KEYS: usize = 128;
const FREE: usize = 0;
const NO_DTOR: usize = 1;

/// Each key's destructor, `NO_DTOR` or `FREE`.
static DTORS: [AtomicUsize; KEYS] = [const { AtomicUsize::new(FREE) }; KEYS];
/// Each key's generation, so that a reused key starts out NULL everywhere.
static GENERATIONS: [AtomicU32; KEYS] = [const { AtomicU32::new(0) }; KEYS];

#[thread_local]
static mut VALUES: [(u32, *mut c_void); KEYS] = [(0, core::ptr::null_mut()); KEYS];

fn values() -> &'static mut [(u32, *mut c_void); KEYS] {
    unsafe { &mut *&raw mut VALUES }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_key_create(key: *mut pthread_key_t, dtor: Option<unsafe extern "C" fn(*mut c_void)>) -> c_int {
    let d = dtor.map_or(NO_DTOR, |f| f as usize);
    for (k, slot) in DTORS.iter().enumerate() {
        if slot.compare_exchange(FREE, d, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            GENERATIONS[k].fetch_add(1, Ordering::Release);
            crate::thread::set_exit_hook(run_dtors);
            unsafe { *key = k as pthread_key_t };
            return 0;
        }
    }
    sys::EAGAIN
}

#[unsafe(no_mangle)]
pub extern "C" fn pthread_key_delete(key: pthread_key_t) -> c_int {
    match DTORS.get(key as usize) {
        Some(slot) if slot.swap(FREE, Ordering::AcqRel) != FREE => 0,
        _ => sys::EINVAL,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn pthread_getspecific(key: pthread_key_t) -> *mut c_void {
    let k = key as usize;
    match values().get(k) {
        Some(&(g, v)) if g == GENERATIONS[k].load(Ordering::Acquire) => v,
        _ => core::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn pthread_setspecific(key: pthread_key_t, v: *const c_void) -> c_int {
    let k = key as usize;
    if k >= KEYS || DTORS[k].load(Ordering::Acquire) == FREE {
        return sys::EINVAL;
    }
    values()[k] = (GENERATIONS[k].load(Ordering::Acquire), v.cast_mut());
    0
}

/// At a thread's exit: each key's destructor on its non-NULL value, in
/// rounds while destructors set values again, as POSIX has it.
fn run_dtors() {
    for _ in 0..4 {
        let mut ran = false;
        for k in 0..KEYS {
            let d = DTORS[k].load(Ordering::Acquire);
            let v = pthread_getspecific(k as pthread_key_t);
            if d > NO_DTOR && !v.is_null() {
                values()[k].1 = core::ptr::null_mut();
                let f: unsafe extern "C" fn(*mut c_void) = unsafe { core::mem::transmute(d) };
                unsafe { f(v) };
                ran = true;
            }
        }
        if !ran {
            break;
        }
    }
}

// ---- reader-writer locks ----

/// musl's `pthread_rwlock_t`, all zeros when initialized.
#[repr(C)]
pub struct pthread_rwlock_t {
    lock: RawRwLock,
    _rest: [c_int; 12],
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_init(l: *mut pthread_rwlock_t, _attr: *const c_void) -> c_int {
    unsafe { l.write_bytes(0, 1) };
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn pthread_rwlock_destroy(_l: *mut pthread_rwlock_t) -> c_int {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_rdlock(l: *mut pthread_rwlock_t) -> c_int {
    unsafe { (*l).lock.read() };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_tryrdlock(l: *mut pthread_rwlock_t) -> c_int {
    if unsafe { (*l).lock.try_read() } { 0 } else { sys::EBUSY }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_wrlock(l: *mut pthread_rwlock_t) -> c_int {
    unsafe { (*l).lock.write() };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_trywrlock(l: *mut pthread_rwlock_t) -> c_int {
    if unsafe { (*l).lock.try_write() } { 0 } else { sys::EBUSY }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_unlock(l: *mut pthread_rwlock_t) -> c_int {
    let l = unsafe { &(*l).lock };
    unsafe {
        if l.is_write_locked() { l.write_unlock() } else { l.read_unlock() }
    }
    0
}

// ---- threads and their stacks ----

/// The thread pointer: unique among live threads.
#[unsafe(no_mangle)]
pub extern "C" fn pthread_self() -> pthread_t {
    crate::arch::thread_pointer()
}

#[unsafe(no_mangle)]
pub extern "C" fn pthread_equal(a: pthread_t, b: pthread_t) -> c_int {
    (a == b) as c_int
}

/// musl's `pthread_attr_t` is 56 bytes; these are its first words.
#[repr(C)]
pub struct pthread_attr_t {
    stack_addr: usize,
    stack_size: usize,
    guard_size: usize,
    _rest: [usize; 4],
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_init(a: *mut pthread_attr_t) -> c_int {
    unsafe { a.write(pthread_attr_t { stack_addr: 0, stack_size: 2 << 20, guard_size: sys::PAGE_SIZE, _rest: [0; 4] }) };
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn pthread_attr_destroy(_a: *mut pthread_attr_t) -> c_int {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_getstack(a: *const pthread_attr_t, addr: *mut *mut c_void, size: *mut size_t) -> c_int {
    unsafe {
        *addr = (*a).stack_addr as *mut c_void;
        *size = (*a).stack_size;
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_getstacksize(a: *const pthread_attr_t, size: *mut size_t) -> c_int {
    unsafe { *size = (*a).stack_size };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_getguardsize(a: *const pthread_attr_t, size: *mut size_t) -> c_int {
    unsafe { *size = (*a).guard_size };
    0
}

/// The main thread's stack, as glibc reports it: from the top of the
/// kernel's stack mapping (above the strings `AT_EXECFN` points into) down
/// by the stack's soft limit.
fn main_stack() -> (usize, usize) {
    let execfn = crate::start::auxv(crate::start::AT_EXECFN).unwrap_or(0);
    let len = if execfn == 0 { 0 } else { unsafe { core::ffi::CStr::from_ptr(execfn as *const _) }.count_bytes() + 1 };
    let top = (execfn + len).next_multiple_of(sys::PAGE_SIZE);
    let limit = super::soft_limit(3 /* RLIMIT_STACK */);
    let size = if limit <= 0 { 8 << 20 } else { limit as usize };
    (top - size.min(top), top)
}

/// The attributes of the calling thread; other threads are not supported.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_getattr_np(t: pthread_t, a: *mut pthread_attr_t) -> c_int {
    if t != pthread_self() {
        return sys::ENOSYS;
    }
    let (low, top) = crate::thread::current_stack().unwrap_or_else(main_stack);
    unsafe { a.write(pthread_attr_t { stack_addr: low, stack_size: top - low, guard_size: sys::PAGE_SIZE, _rest: [0; 4] }) };
    0
}

// ---- fork handlers ----

type Handler = Option<unsafe extern "C" fn()>;

struct Handlers {
    lock: RawMutex,
    list: core::cell::UnsafeCell<([[Handler; 3]; 32], usize)>,
}

unsafe impl Sync for Handlers {}

static AT_FORK: Handlers = Handlers { lock: RawMutex::new(), list: core::cell::UnsafeCell::new(([[None; 3]; 32], 0)) };

#[unsafe(no_mangle)]
pub extern "C" fn pthread_atfork(prepare: Handler, parent: Handler, child: Handler) -> c_int {
    AT_FORK.lock.lock();
    let (list, n) = unsafe { &mut *AT_FORK.list.get() };
    let r = if *n < list.len() {
        list[*n] = [prepare, parent, child];
        *n += 1;
        0
    } else {
        sys::ENOMEM
    };
    unsafe { AT_FORK.lock.unlock() };
    r
}

/// Run `fork` between the handlers: the prepare ones last registered
/// first, then the parent's or the child's in order.
pub(super) fn with_handlers(fork: impl FnOnce() -> isize) -> isize {
    AT_FORK.lock.lock();
    let (list, n) = unsafe { *AT_FORK.list.get() };
    unsafe { AT_FORK.lock.unlock() };
    for h in list[..n].iter().rev() {
        if let Some(f) = h[0] {
            unsafe { f() };
        }
    }
    let pid = fork();
    let which = if pid == 0 { 2 } else { 1 };
    for h in &list[..n] {
        if let Some(f) = h[which] {
            unsafe { f() };
        }
    }
    pid
}

// ---- once ----

const ONCE_NEW: u32 = 0;
const ONCE_RUNNING: u32 = 1;
const ONCE_WAITED: u32 = 2;
const ONCE_DONE: u32 = 3;

/// musl's `pthread_once_t` is an int, 0 before the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_once(once: *mut AtomicU32, init: unsafe extern "C" fn()) -> c_int {
    let once = unsafe { &*once };
    loop {
        match once.compare_exchange(ONCE_NEW, ONCE_RUNNING, Ordering::Acquire, Ordering::Acquire) {
            Ok(_) => {
                unsafe { init() };
                if once.swap(ONCE_DONE, Ordering::Release) == ONCE_WAITED {
                    crate::futex::wake_all(once);
                }
                return 0;
            }
            Err(ONCE_DONE) => return 0,
            Err(s) => {
                // running: say there is a waiter, then sleep until done
                if s == ONCE_WAITED || once.compare_exchange(ONCE_RUNNING, ONCE_WAITED, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                    crate::futex::wait(once, ONCE_WAITED, None);
                }
            }
        }
    }
}
