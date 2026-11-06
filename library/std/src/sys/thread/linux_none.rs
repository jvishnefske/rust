//! Threads on linux-none: `linux_none_rt::thread` (clone, a guard page, TLS
//! from the executable's `PT_TLS`). As on hermit, std is the only runtime, so
//! a thread runs its TLS destructors itself once its main function returns.

use linux_none_rt::sys;

use crate::ffi::CStr;
use crate::num::NonZero;
use crate::thread::ThreadInit;
use crate::time::Duration;
use crate::{cmp, io};

pub const DEFAULT_MIN_STACK_SIZE: usize = 2 * 1024 * 1024;

pub struct Thread {
    native: Option<linux_none_rt::thread::Thread>,
}

unsafe impl Send for Thread {}
unsafe impl Sync for Thread {}

impl Thread {
    // unsafe: see thread::Builder::spawn_unchecked for safety requirements
    pub unsafe fn new(stack: usize, init: Box<ThreadInit>) -> io::Result<Thread> {
        let data = Box::into_raw(init);
        return match unsafe { linux_none_rt::thread::spawn(stack, thread_start, data.cast()) } {
            Ok(native) => Ok(Thread { native: Some(native) }),
            Err(e) => {
                // The thread failed to start and as a result `data` was not consumed.
                // Therefore, it is safe to reconstruct the box so that it gets deallocated.
                drop(unsafe { Box::from_raw(data) });
                Err(io::Error::from_raw_os_error(e))
            }
        };

        unsafe fn thread_start(data: *mut u8) {
            // SAFETY: we are simply recreating the box that was leaked earlier.
            let init = unsafe { Box::from_raw(data as *mut ThreadInit) };
            let rust_start = init.init();
            rust_start();
            crate::sys::pal::run_thread_exit();
        }
    }

    pub fn join(mut self) {
        self.native.take().unwrap().join();
    }
}

impl Drop for Thread {
    fn drop(&mut self) {
        if let Some(native) = self.native.take() {
            native.detach();
        }
    }
}

pub fn available_parallelism() -> io::Result<NonZero<usize>> {
    // the affinity mask, up to 8192 CPUs
    let mut set = [0u64; 128];
    let n = crate::sys::cvt(unsafe { sys::sched_getaffinity(set.as_mut_ptr().cast(), size_of_val(&set)) })?;
    let count: usize = set[..n / 8].iter().map(|w| w.count_ones() as usize).sum();
    NonZero::new(count).ok_or(io::Error::UNKNOWN_THREAD_COUNT)
}

pub fn current_os_id() -> Option<u64> {
    Some(sys::gettid() as u64)
}

pub fn set_name(name: &CStr) {
    const PR_SET_NAME: usize = 15;
    // the kernel truncates the name to 15 bytes
    let _ = unsafe { sys::prctl(PR_SET_NAME, name.as_ptr() as usize, 0, 0, 0) };
}

pub fn sleep(dur: Duration) {
    let mut secs = dur.as_secs();
    let mut nsecs = dur.subsec_nanos() as i64;
    while secs > 0 || nsecs > 0 {
        let chunk = cmp::min(i64::MAX as u64, secs);
        secs -= chunk;
        // retries on EINTR with the remaining time
        let _ = sys::nanosleep(&sys::Timespec { sec: chunk as i64, nsec: nsecs });
        nsecs = 0;
    }
}

pub fn sleep_until(deadline: crate::time::Instant) {
    let timespec = deadline.into_inner().into_timespec();
    if timespec.tv_sec < 0 {
        // a negative CLOCK_MONOTONIC time is in the past
        return;
    }
    let ts = sys::Timespec { sec: timespec.tv_sec, nsec: timespec.tv_nsec.as_inner() as i64 };
    loop {
        let r = unsafe {
            sys::clock_nanosleep(sys::CLOCK_MONOTONIC, sys::TIMER_ABSTIME, &ts, crate::ptr::null_mut())
        };
        match r {
            Err(sys::EINTR) => continue,
            r => {
                assert!(r.is_ok(), "timespec is in range, clock_nanosleep should not fail");
                return;
            }
        }
    }
}

pub fn yield_now() {
    sys::sched_yield()
}
