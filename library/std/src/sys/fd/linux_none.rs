//! `FileDesc` on linux-none: fd/unix.rs on `linux_none_rt` syscalls.

#![unstable(reason = "not public", issue = "none", feature = "fd")]

#[cfg(test)]
#[path = "unix/tests.rs"]
mod tests;

use linux_none_rt::sys::{self, IoVec};

use crate::cmp;
use crate::io::{self, BorrowedCursor, IoSlice, IoSliceMut, Read};
use crate::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use crate::sys::{AsInner, FromInner, IntoInner, cvt};

#[derive(Debug)]
pub struct FileDesc(OwnedFd);

// Reads and writes larger than `ssize_t::MAX` are unspecified.
const READ_LIMIT: usize = isize::MAX as usize;

const fn max_iov() -> usize {
    libc::UIO_MAXIOV as usize
}

// `IoSlice` and `IoSliceMut` are ABI-compatible with `struct iovec` on unix
fn iov(bufs: &[IoSlice<'_>]) -> (*const IoVec, usize) {
    (bufs.as_ptr().cast(), cmp::min(bufs.len(), max_iov()))
}

fn iov_mut(bufs: &mut [IoSliceMut<'_>]) -> (*const IoVec, usize) {
    (bufs.as_mut_ptr().cast_const().cast(), cmp::min(bufs.len(), max_iov()))
}

impl FileDesc {
    #[inline]
    pub fn try_clone(&self) -> io::Result<Self> {
        self.duplicate()
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let len = cmp::min(buf.len(), READ_LIMIT);
        cvt(unsafe { sys::read(self.as_raw_fd(), buf.as_mut_ptr(), len) })
    }

    pub fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        let (p, n) = iov_mut(bufs);
        cvt(unsafe { sys::readv(self.as_raw_fd(), p, n) })
    }

    #[inline]
    pub fn is_read_vectored(&self) -> bool {
        true
    }

    pub fn read_to_end(&self, buf: &mut Vec<u8>) -> io::Result<usize> {
        let mut me = self;
        (&mut me).read_to_end(buf)
    }

    pub fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let len = cmp::min(buf.len(), READ_LIMIT);
        // EINVAL if offset + count overflows
        cvt(unsafe { sys::pread(self.as_raw_fd(), buf.as_mut_ptr(), len, offset) })
    }

    pub fn read_buf(&self, mut cursor: BorrowedCursor<'_, u8>) -> io::Result<()> {
        // SAFETY: `cursor.as_mut()` starts with `cursor.capacity()` writable bytes
        let ret = cvt(unsafe {
            sys::read(
                self.as_raw_fd(),
                cursor.as_mut().as_mut_ptr().cast::<u8>(),
                cmp::min(cursor.capacity(), READ_LIMIT),
            )
        })?;

        // SAFETY: `ret` bytes were written to the initialized portion of the buffer
        unsafe {
            cursor.advance(ret);
        }
        Ok(())
    }

    pub fn read_buf_at(&self, mut cursor: BorrowedCursor<'_, u8>, offset: u64) -> io::Result<()> {
        // SAFETY: `cursor.as_mut()` starts with `cursor.capacity()` writable bytes
        let ret = cvt(unsafe {
            sys::pread(
                self.as_raw_fd(),
                cursor.as_mut().as_mut_ptr().cast::<u8>(),
                cmp::min(cursor.capacity(), READ_LIMIT),
                offset,
            )
        })?;

        // SAFETY: `ret` bytes were written to the initialized portion of the buffer
        unsafe {
            cursor.advance(ret);
        }
        Ok(())
    }

    pub fn read_vectored_at(&self, bufs: &mut [IoSliceMut<'_>], offset: u64) -> io::Result<usize> {
        let (p, n) = iov_mut(bufs);
        cvt(unsafe { sys::preadv(self.as_raw_fd(), p, n, offset) })
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let len = cmp::min(buf.len(), READ_LIMIT);
        cvt(unsafe { sys::write(self.as_raw_fd(), buf.as_ptr(), len) })
    }

    pub fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        let (p, n) = iov(bufs);
        cvt(unsafe { sys::writev(self.as_raw_fd(), p, n) })
    }

    #[inline]
    pub fn is_write_vectored(&self) -> bool {
        true
    }

    pub fn write_at(&self, buf: &[u8], offset: u64) -> io::Result<usize> {
        let len = cmp::min(buf.len(), READ_LIMIT);
        cvt(unsafe { sys::pwrite(self.as_raw_fd(), buf.as_ptr(), len, offset) })
    }

    pub fn write_vectored_at(&self, bufs: &[IoSlice<'_>], offset: u64) -> io::Result<usize> {
        let (p, n) = iov(bufs);
        cvt(unsafe { sys::pwritev(self.as_raw_fd(), p, n, offset) })
    }

    pub fn set_cloexec(&self) -> io::Result<()> {
        let fd = self.as_raw_fd();
        let previous = cvt(sys::fcntl(fd, sys::F_GETFD, 0))?;
        let new = previous | sys::FD_CLOEXEC;
        if new != previous {
            cvt(sys::fcntl(fd, sys::F_SETFD, new))?;
        }
        Ok(())
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        let v = nonblocking as libc::c_int;
        cvt(unsafe { sys::ioctl(self.as_raw_fd(), libc::FIONBIO as usize, &v as *const _ as usize) })?;
        Ok(())
    }

    #[inline]
    pub fn duplicate(&self) -> io::Result<FileDesc> {
        Ok(Self(self.0.try_clone()?))
    }
}

impl<'a> Read for &'a FileDesc {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (**self).read(buf)
    }

    fn read_buf(&mut self, cursor: BorrowedCursor<'_, u8>) -> io::Result<()> {
        (**self).read_buf(cursor)
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        (**self).read_vectored(bufs)
    }

    #[inline]
    fn is_read_vectored(&self) -> bool {
        (**self).is_read_vectored()
    }
}

impl AsInner<OwnedFd> for FileDesc {
    #[inline]
    fn as_inner(&self) -> &OwnedFd {
        &self.0
    }
}

impl IntoInner<OwnedFd> for FileDesc {
    fn into_inner(self) -> OwnedFd {
        self.0
    }
}

impl FromInner<OwnedFd> for FileDesc {
    fn from_inner(owned_fd: OwnedFd) -> Self {
        Self(owned_fd)
    }
}

impl AsFd for FileDesc {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl AsRawFd for FileDesc {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl IntoRawFd for FileDesc {
    fn into_raw_fd(self) -> RawFd {
        self.0.into_raw_fd()
    }
}

impl FromRawFd for FileDesc {
    unsafe fn from_raw_fd(raw_fd: RawFd) -> Self {
        Self(unsafe { FromRawFd::from_raw_fd(raw_fd) })
    }
}
