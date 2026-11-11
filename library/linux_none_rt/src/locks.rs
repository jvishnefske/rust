//! Futex-based lock primitives shared by `sync`, the allocator and stdio.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering::{Acquire, Relaxed, Release, SeqCst};
use core::time::Duration;

use crate::futex;

const UNLOCKED: u32 = 0;
const LOCKED: u32 = 1;
const CONTENDED: u32 = 2;

#[repr(transparent)] // so that clib can lay it over a pthread_mutex_t
pub struct RawMutex {
    state: AtomicU32,
}

impl RawMutex {
    pub const fn new() -> Self {
        RawMutex { state: AtomicU32::new(UNLOCKED) }
    }

    #[inline]
    pub fn try_lock(&self) -> bool {
        self.state.compare_exchange(UNLOCKED, LOCKED, Acquire, Relaxed).is_ok()
    }

    #[inline]
    pub fn lock(&self) {
        if !self.try_lock() {
            self.lock_contended();
        }
    }

    #[cold]
    fn lock_contended(&self) {
        let mut state = self.spin();
        if state == UNLOCKED {
            match self.state.compare_exchange(UNLOCKED, LOCKED, Acquire, Relaxed) {
                Ok(_) => return,
                Err(s) => state = s,
            }
        }
        loop {
            if state != CONTENDED && self.state.swap(CONTENDED, Acquire) == UNLOCKED {
                return;
            }
            futex::wait(&self.state, CONTENDED, None);
            state = self.spin();
        }
    }

    fn spin(&self) -> u32 {
        let mut n = 100;
        loop {
            let s = self.state.load(Relaxed);
            if s != LOCKED || n == 0 {
                return s;
            }
            core::hint::spin_loop();
            n -= 1;
        }
    }

    /// # Safety
    /// The calling thread must hold the lock.
    #[inline]
    pub unsafe fn unlock(&self) {
        if self.state.swap(UNLOCKED, Release) == CONTENDED {
            futex::wake_one(&self.state);
        }
    }
}

/// Condition variable: a sequence number that waiters sleep on.
pub struct RawCondvar {
    seq: AtomicU32,
}

impl RawCondvar {
    pub const fn new() -> Self {
        RawCondvar { seq: AtomicU32::new(0) }
    }

    pub fn notify_one(&self) {
        self.seq.fetch_add(1, Relaxed);
        futex::wake_one(&self.seq);
    }

    pub fn notify_all(&self) {
        self.seq.fetch_add(1, Relaxed);
        futex::wake_all(&self.seq);
    }

    /// # Safety
    /// `m` must be locked by the calling thread. Returns false on timeout.
    pub unsafe fn wait(&self, m: &RawMutex, timeout: Option<Duration>) -> bool {
        let seq = self.seq.load(Relaxed);
        unsafe { m.unlock() };
        let r = futex::wait(&self.seq, seq, timeout);
        m.lock();
        r
    }
}

/// Reader-writer lock. State: number of readers, or `WRITER`.
/// Waiters all sleep on `state` and are all woken on release; simple and
/// correct, at the cost of thundering herds under heavy contention.
#[repr(C)] // so that clib can lay it over a pthread_rwlock_t
pub struct RawRwLock {
    state: AtomicU32,
    waiters: AtomicU32,
}

const WRITER: u32 = u32::MAX;

impl RawRwLock {
    pub const fn new() -> Self {
        RawRwLock { state: AtomicU32::new(0), waiters: AtomicU32::new(0) }
    }

    pub fn try_read(&self) -> bool {
        let s = self.state.load(Relaxed);
        s < WRITER - 1 && self.state.compare_exchange_weak(s, s + 1, Acquire, Relaxed).is_ok()
    }

    pub fn read(&self) {
        loop {
            let s = self.state.load(Relaxed);
            if s < WRITER - 1 {
                if self.state.compare_exchange_weak(s, s + 1, Acquire, Relaxed).is_ok() {
                    return;
                }
                continue;
            }
            self.sleep(s);
        }
    }

    /// Whether a writer holds it (else readers, or nobody).
    pub fn is_write_locked(&self) -> bool {
        self.state.load(Relaxed) == WRITER
    }

    pub fn try_write(&self) -> bool {
        self.state.compare_exchange(0, WRITER, Acquire, Relaxed).is_ok()
    }

    pub fn write(&self) {
        loop {
            match self.state.compare_exchange_weak(0, WRITER, Acquire, Relaxed) {
                Ok(_) => return,
                Err(s) => {
                    if s != 0 {
                        self.sleep(s)
                    }
                }
            }
        }
    }

    fn sleep(&self, seen: u32) {
        self.waiters.fetch_add(1, SeqCst);
        futex::wait(&self.state, seen, None);
        self.waiters.fetch_sub(1, Relaxed);
    }

    /// # Safety
    /// The calling thread must hold a read lock.
    pub unsafe fn read_unlock(&self) {
        if self.state.fetch_sub(1, SeqCst) == 1 && self.waiters.load(SeqCst) != 0 {
            futex::wake_all(&self.state);
        }
    }

    /// # Safety
    /// The calling thread must hold the write lock.
    pub unsafe fn write_unlock(&self) {
        self.state.store(0, SeqCst);
        if self.waiters.load(SeqCst) != 0 {
            futex::wake_all(&self.state);
        }
    }
}
