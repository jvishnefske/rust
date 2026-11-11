//! The thread's `errno`, which std's `io::Error::last_os_error` reads and
//! its syscall wrappers set.
//!
//! It lives here rather than in std for the reason libc's does: every copy
//! of std linked into a program must see the same one. (std's own unit tests
//! link two: the std under test, and the sysroot's, whose `io::Error`
//! methods they call.)

#[thread_local]
static mut ERRNO: i32 = 0;

/// The address of the calling thread's errno (unique per thread).
#[inline]
pub fn location() -> *mut i32 {
    &raw mut ERRNO
}
