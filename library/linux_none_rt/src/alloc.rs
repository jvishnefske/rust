//! A small mmap-backed allocator: power-of-two size classes with free lists
//! for blocks up to 32 KiB, direct `mmap` for everything larger.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr::null_mut;

use crate::sys::{self as linux, MAP_ANONYMOUS, MAP_PRIVATE, PAGE_SIZE, PROT_READ, PROT_WRITE};
use crate::locks::RawMutex;

const MIN_SHIFT: u32 = 4; // 16 bytes
const MAX_SHIFT: u32 = 15; // 32 KiB
const NCLASSES: usize = (MAX_SHIFT - MIN_SHIFT + 1) as usize;
const CHUNK: usize = 1 << 20;

pub struct Allocator {
    lock: RawMutex,
    state: UnsafeCell<State>,
}

struct State {
    free: [*mut u8; NCLASSES],
    bump: usize,
    end: usize,
}

unsafe impl Sync for Allocator {}

/// Size class index for a layout, or None if it goes straight to mmap.
#[inline]
fn class_of(layout: &Layout) -> Option<usize> {
    let size = layout.size().max(layout.align()).max(1 << MIN_SHIFT);
    if size > 1 << MAX_SHIFT || layout.align() > PAGE_SIZE {
        return None;
    }
    let shift = usize::BITS - (size - 1).leading_zeros();
    Some((shift - MIN_SHIFT) as usize)
}

#[inline]
fn round_up(n: usize, to: usize) -> usize {
    (n + to - 1) & !(to - 1)
}

unsafe fn map(len: usize) -> *mut u8 {
    match unsafe { linux::mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) } {
        Ok(p) => p as *mut u8,
        Err(_) => null_mut(),
    }
}

impl Allocator {
    pub const fn new() -> Self {
        Allocator {
            lock: RawMutex::new(),
            state: UnsafeCell::new(State { free: [null_mut(); NCLASSES], bump: 0, end: 0 }),
        }
    }

    unsafe fn alloc_small(&self, class: usize) -> *mut u8 {
        let size = 1usize << (class as u32 + MIN_SHIFT);
        self.lock.lock();
        let st = unsafe { &mut *self.state.get() };
        let head = st.free[class];
        let p = if !head.is_null() {
            st.free[class] = unsafe { *(head as *mut *mut u8) };
            head
        } else {
            // every block of a class is aligned to min(size, page) so that any
            // layout mapping to the class is satisfied by any of its blocks
            let align = size.min(PAGE_SIZE);
            let mut start = round_up(st.bump, align);
            if st.bump == 0 || start + size > st.end {
                let chunk = unsafe { map(CHUNK) } as usize;
                if chunk == 0 {
                    unsafe { self.lock.unlock() };
                    return null_mut();
                }
                st.bump = chunk;
                st.end = chunk + CHUNK;
                start = chunk;
            }
            st.bump = start + size;
            start as *mut u8
        };
        unsafe { self.lock.unlock() };
        p
    }

    unsafe fn alloc_large(layout: Layout) -> *mut u8 {
        let len = round_up(layout.size(), PAGE_SIZE);
        if layout.align() <= PAGE_SIZE {
            return unsafe { map(len) };
        }
        // over-allocate, then trim to the requested alignment
        let total = len + layout.align();
        let base = unsafe { map(total) } as usize;
        if base == 0 {
            return null_mut();
        }
        let start = round_up(base, layout.align());
        unsafe {
            if start > base {
                let _ = linux::munmap(base, start - base);
            }
            let tail = start + len;
            if base + total > tail {
                let _ = linux::munmap(tail, base + total - tail);
            }
        }
        start as *mut u8
    }
}

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        match class_of(&layout) {
            Some(c) => unsafe { self.alloc_small(c) },
            None => unsafe { Self::alloc_large(layout) },
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        match class_of(&layout) {
            Some(c) => {
                self.lock.lock();
                let st = unsafe { &mut *self.state.get() };
                unsafe { *(ptr as *mut *mut u8) = st.free[c] };
                st.free[c] = ptr;
                unsafe { self.lock.unlock() };
            }
            None => unsafe {
                let _ = linux::munmap(ptr as usize, round_up(layout.size(), PAGE_SIZE));
            },
        }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        match class_of(&layout) {
            Some(c) => {
                let p = unsafe { self.alloc_small(c) };
                if !p.is_null() {
                    unsafe { core::ptr::write_bytes(p, 0, layout.size()) };
                }
                p
            }
            // fresh anonymous mappings are already zeroed
            None => unsafe { Self::alloc_large(layout) },
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        let old = class_of(&layout);
        if old.is_some() && old == class_of(&new_layout) {
            return ptr;
        }
        if old.is_none() && class_of(&new_layout).is_none() && layout.align() <= PAGE_SIZE
            && round_up(layout.size(), PAGE_SIZE) == round_up(new_size, PAGE_SIZE)
        {
            return ptr;
        }
        let new = unsafe { self.alloc(new_layout) };
        if !new.is_null() {
            unsafe {
                core::ptr::copy_nonoverlapping(ptr, new, layout.size().min(new_size));
                self.dealloc(ptr, layout);
            }
        }
        new
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Every layout either goes to mmap or gets a size class whose blocks are
    /// big enough and aligned enough (blocks of class `c` are aligned to
    /// min(block size, page)), and no smaller class would do.
    #[kani::proof]
    fn size_class_fits_layout() {
        let size: usize = kani::any_where(|&s| s <= 1 << 40);
        let shift: u32 = kani::any_where(|&k| k <= 20);
        let layout = Layout::from_size_align(size, 1 << shift).unwrap();
        let need = size.max(layout.align()).max(1 << MIN_SHIFT);
        match class_of(&layout) {
            Some(c) => {
                assert!(c < NCLASSES);
                let block = 1usize << (c as u32 + MIN_SHIFT);
                assert!(block >= need);
                assert!(block.min(PAGE_SIZE) % layout.align() == 0);
                assert!(c == 0 || block / 2 < need);
            }
            None => assert!(need > 1 << MAX_SHIFT || layout.align() > PAGE_SIZE),
        }
    }

    /// `realloc` keeps the block when the class is unchanged: then the block
    /// must also hold the new size.
    #[kani::proof]
    fn same_class_realloc_fits() {
        let (old, new): (usize, usize) = (kani::any_where(|&s| s <= 1 << 20), kani::any_where(|&s| s <= 1 << 20));
        let align = 1usize << kani::any_where(|&k: &u32| k <= 13);
        let (a, b) = (Layout::from_size_align(old, align).unwrap(), Layout::from_size_align(new, align).unwrap());
        if let (Some(c), Some(d)) = (class_of(&a), class_of(&b)) {
            if c == d {
                assert!(1usize << (c as u32 + MIN_SHIFT) >= new);
            }
        }
    }

    #[kani::proof]
    fn round_up_is_least_multiple() {
        let n: usize = kani::any_where(|&n| n <= usize::MAX / 2);
        let to = 1usize << kani::any_where(|&k: &u32| k <= 12);
        let r = round_up(n, to);
        assert!(r >= n && r % to == 0 && r - n < to);
    }
}
