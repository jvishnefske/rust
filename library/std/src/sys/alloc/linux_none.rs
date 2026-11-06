//! `System` on linux-none: `linux_none_rt`'s mmap-backed allocator.

use linux_none_rt::alloc::Allocator;

use crate::alloc::{GlobalAlloc, Layout};

static ALLOCATOR: Allocator = Allocator::new();

#[inline]
pub unsafe fn alloc(layout: Layout) -> *mut u8 {
    unsafe { ALLOCATOR.alloc(layout) }
}

#[inline]
pub unsafe fn alloc_zeroed(layout: Layout) -> *mut u8 {
    unsafe { ALLOCATOR.alloc_zeroed(layout) }
}

#[inline]
pub unsafe fn dealloc(ptr: *mut u8, layout: Layout) {
    unsafe { ALLOCATOR.dealloc(ptr, layout) }
}

#[inline]
pub unsafe fn realloc(ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
    unsafe { ALLOCATOR.realloc(ptr, layout, new_size) }
}
