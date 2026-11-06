//! What `linux.rs` takes from libc, on `linux_none_rt` syscalls: the three
//! copy syscalls with libc's signatures and conventions (`-1` and errno on
//! failure), and a `cvt` for that convention.

use libc::{c_int, c_uint, size_t, ssize_t};
use linux_none_rt::sys;

use crate::io;
use crate::sys::io::set_errno;

fn ret(r: Result<usize, i32>) -> ssize_t {
    match r {
        Ok(v) => v as ssize_t,
        Err(e) => {
            set_errno(e);
            -1
        }
    }
}

/// `-1` means failure, with the error in errno.
pub fn cvt(r: ssize_t) -> io::Result<ssize_t> {
    if r == -1 { Err(io::Error::last_os_error()) } else { Ok(r) }
}

pub unsafe fn copy_file_range(
    fd_in: c_int,
    off_in: *mut i64,
    fd_out: c_int,
    off_out: *mut i64,
    len: size_t,
    flags: c_uint,
) -> ssize_t {
    ret(unsafe { sys::copy_file_range(fd_in, off_in, fd_out, off_out, len, flags) })
}

pub unsafe fn sendfile64(out_fd: c_int, in_fd: c_int, offset: *mut i64, count: size_t) -> ssize_t {
    ret(unsafe { sys::sendfile(out_fd, in_fd, offset, count) })
}

pub unsafe fn splice(
    fd_in: c_int,
    off_in: *mut i64,
    fd_out: c_int,
    off_out: *mut i64,
    len: size_t,
    flags: c_uint,
) -> ssize_t {
    ret(unsafe { sys::splice(fd_in, off_in, fd_out, off_out, len, flags) })
}
