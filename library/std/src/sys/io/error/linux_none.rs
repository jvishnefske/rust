//! errno on linux-none: there is no libc errno, but `io::Error::last_os_error`
//! and `set_errno` still need one, so it is a thread-local (in the runtime,
//! shared by every copy of std in the program) that the syscall wrappers'
//! `cvt` records failures in.

use crate::ffi::c_int;
use crate::{fmt, io};

/// The address of this thread's errno (unique per thread).
#[inline]
pub fn errno_location() -> *mut c_int {
    linux_none_rt::errno::location()
}

#[inline]
pub fn errno() -> i32 {
    unsafe { *errno_location() }
}

#[inline]
pub fn set_errno(e: i32) {
    unsafe { *errno_location() = e }
}

#[inline]
pub fn is_interrupted(errno: i32) -> bool {
    errno == libc::EINTR
}

pub fn decode_error_kind(errno: i32) -> io::ErrorKind {
    use io::ErrorKind::*;
    match errno as libc::c_int {
        libc::E2BIG => ArgumentListTooLong,
        libc::EADDRINUSE => AddrInUse,
        libc::EADDRNOTAVAIL => AddrNotAvailable,
        libc::EBUSY => ResourceBusy,
        libc::ECONNABORTED => ConnectionAborted,
        libc::ECONNREFUSED => ConnectionRefused,
        libc::ECONNRESET => ConnectionReset,
        libc::EDEADLK => Deadlock,
        libc::EDQUOT => QuotaExceeded,
        libc::EEXIST => AlreadyExists,
        libc::EFBIG => FileTooLarge,
        libc::EHOSTUNREACH => HostUnreachable,
        libc::EINTR => Interrupted,
        libc::EINVAL => InvalidInput,
        libc::EISDIR => IsADirectory,
        libc::ELOOP => FilesystemLoop,
        libc::ENOENT => NotFound,
        libc::ENOMEM => OutOfMemory,
        libc::ENOSPC => StorageFull,
        libc::EMLINK => TooManyLinks,
        libc::ENAMETOOLONG => InvalidFilename,
        libc::ENETDOWN => NetworkDown,
        libc::ENETUNREACH => NetworkUnreachable,
        libc::ENOTCONN => NotConnected,
        libc::ENOTDIR => NotADirectory,
        #[cfg(not(target_os = "aix"))]
        libc::ENOTEMPTY => DirectoryNotEmpty,
        libc::EPIPE => BrokenPipe,
        libc::EROFS => ReadOnlyFilesystem,
        libc::ESPIPE => NotSeekable,
        libc::ESTALE => StaleNetworkFileHandle,
        libc::ETIMEDOUT => TimedOut,
        libc::ETXTBSY => ExecutableFileBusy,
        libc::EXDEV => CrossesDevices,
        libc::EINPROGRESS => InProgress,
        libc::EMFILE | libc::ENFILE => TooManyOpenFiles,
        libc::EIO => InputOutputError,

        libc::EACCES | libc::EPERM => PermissionDenied,

        libc::ENOSYS => Unsupported,
        // EOPNOTSUPP and ENOTSUP can have the same value on some systems,
        // but different values on others (e.g. Apple), so we can't use a
        // match clause
        x if x == libc::EOPNOTSUPP || x == libc::ENOTSUP => Unsupported,

        // These two constants can have the same value on some systems,
        // but different values on others, so we can't use a match
        // clause
        x if x == libc::EAGAIN || x == libc::EWOULDBLOCK => WouldBlock,

        _ => Uncategorized,
    }
}

/// Gets a detailed string description for the given error number.
pub fn format_error(errno: i32, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(linux_none_rt::sys::strerror(errno))
}
