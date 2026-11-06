use linux_none_rt::sys;

use crate::sync::atomic::Atomic;
use crate::sync::atomic::Ordering::Relaxed;
use crate::sys::pal::time::Timespec;
use crate::time::Duration;

/// An atomic for use as a futex that is at least 32-bits but may be larger
pub type Futex = Atomic<Primitive>;
/// Must be the underlying type of Futex
pub type Primitive = u32;

/// An atomic for use as a futex that is at least 8-bits but may be larger.
pub type SmallFutex = Atomic<SmallPrimitive>;
/// Must be the underlying type of SmallFutex
pub type SmallPrimitive = u32;

/// Waits for a `futex_wake` operation to wake us.
///
/// Returns directly if the futex doesn't hold the expected value.
///
/// Returns false on timeout, and true in all other cases.
pub fn futex_wait(futex: &Atomic<u32>, expected: u32, timeout: Option<Duration>) -> bool {
    // An absolute deadline, so that retrying after EINTR does not extend the
    // wait. Overflows are rounded up to an infinite timeout (None).
    let deadline = timeout
        .and_then(|d| Timespec::now(libc::CLOCK_MONOTONIC).checked_add_duration(&d))
        .and_then(|t| t.to_timespec())
        .map(|t| sys::Timespec { sec: t.tv_sec, nsec: t.tv_nsec });

    loop {
        // No need to wait if the value already changed.
        if futex.load(Relaxed) != expected {
            return true;
        }
        let ts = deadline.as_ref().map_or(crate::ptr::null(), |t| t as *const sys::Timespec);
        match unsafe { sys::futex_wait_abs(futex.as_ptr(), expected, ts) } {
            Err(sys::ETIMEDOUT) => return false,
            Err(sys::EINTR) => continue,
            _ => return true,
        }
    }
}

/// Wakes up one thread that's blocked on `futex_wait` on this futex.
///
/// Returns true if this actually woke up such a thread,
/// or false if no thread was waiting on this futex.
pub fn futex_wake(futex: &Atomic<u32>) -> bool {
    linux_none_rt::futex::wake_one(futex)
}

/// Wakes up all threads that are waiting on `futex_wait` on this futex.
pub fn futex_wake_all(futex: &Atomic<u32>) {
    linux_none_rt::futex::wake_all(futex)
}
