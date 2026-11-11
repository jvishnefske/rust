//! Futex wait and wake on private (or, for thread exit, shared) futexes.

use core::sync::atomic::AtomicU32;
use core::time::Duration;

use crate::sys::{self as linux, FUTEX_PRIVATE, FUTEX_WAIT, FUTEX_WAKE, Timespec};

fn to_timespec(d: Duration) -> Timespec {
    Timespec { sec: d.as_secs().min(i64::MAX as u64) as i64, nsec: d.subsec_nanos() as i64 }
}

/// Sleep while `*a == expected`. Returns false on timeout.
/// Spurious wakeups are possible; callers re-check their condition.
pub fn wait(a: &AtomicU32, expected: u32, timeout: Option<Duration>) -> bool {
    wait_op(a, expected, timeout, FUTEX_WAIT | FUTEX_PRIVATE)
}

/// Like [`wait`], but on a process-shared futex. The kernel wakes
/// `CLONE_CHILD_CLEARTID` addresses as shared futexes.
pub fn wait_shared(a: &AtomicU32, expected: u32) {
    wait_op(a, expected, None, FUTEX_WAIT);
}

fn wait_op(a: &AtomicU32, expected: u32, timeout: Option<Duration>, op: usize) -> bool {
    let ts = timeout.map(to_timespec);
    let tsp = ts.as_ref().map_or(core::ptr::null(), |t| t as *const Timespec);
    !matches!(unsafe { linux::futex(a.as_ptr(), op, expected, tsp) }, Err(linux::ETIMEDOUT))
}

/// Wake one waiter. Returns whether a thread was woken.
pub fn wake_one(a: &AtomicU32) -> bool {
    unsafe { linux::futex(a.as_ptr(), FUTEX_WAKE | FUTEX_PRIVATE, 1, core::ptr::null()) }.is_ok_and(|n| n > 0)
}

pub fn wake_all(a: &AtomicU32) {
    let _ = unsafe { linux::futex(a.as_ptr(), FUTEX_WAKE | FUTEX_PRIVATE, i32::MAX as u32, core::ptr::null()) };
}
