//! Files on linux-none: fs/unix.rs for Linux, on `linux_none_rt` syscalls.
//! Metadata comes from `statx`, directories are read with `getdents64`, and
//! `canonicalize` resolves symlinks itself, as glibc's `realpath` does.

#![allow(nonstandard_style)]

#[cfg(test)]
#[path = "unix/tests.rs"]
mod tests;

use libc::{c_int, mode_t, stat64};
use linux_none_rt::{dirent, sys};

use crate::ffi::{CStr, CString, OsStr, OsString};
use crate::fmt::{self, Write as _};
use crate::fs::TryLockError;
use crate::io::{self, BorrowedCursor, IoSlice, IoSliceMut, SeekFrom};
use crate::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};
use crate::os::unix::prelude::*;
use crate::path::{Path, PathBuf};
use crate::sync::Arc;
use crate::sys::fd::FileDesc;
pub use crate::sys::fs::common::exists;
use crate::sys::helpers::run_path_with_cstr;
use crate::sys::time::SystemTime;
use crate::sys::{AsInner, AsInnerMut, FromInner, IntoInner, cvt, cvt_r};
use crate::{fs, mem, ptr};

pub struct File(FileDesc);

#[derive(Clone)]
pub struct FileAttr {
    stat: stat64,
    /// birth time, when the filesystem reports one
    btime: Option<sys::StatxTimestamp>,
}

/// `statx`, translated to the `stat64` that `MetadataExt` exposes.
fn statx(dirfd: c_int, path: &CStr, flags: u32) -> io::Result<FileAttr> {
    let mut buf = sys::Statx::default();
    cvt(unsafe {
        sys::statx(
            dirfd,
            path.as_ptr().cast(),
            flags | AT_STATX_SYNC_AS_STAT,
            sys::STATX_BASIC_STATS | sys::STATX_BTIME,
            &mut buf,
        )
    })?;

    // We cannot fill `stat64` exhaustively because of private padding fields.
    let mut stat: stat64 = unsafe { mem::zeroed() };
    stat.st_dev = libc::makedev(buf.dev_major, buf.dev_minor) as _;
    stat.st_ino = buf.ino as _;
    stat.st_nlink = buf.nlink as _;
    stat.st_mode = buf.mode as mode_t;
    stat.st_uid = buf.uid;
    stat.st_gid = buf.gid;
    stat.st_rdev = libc::makedev(buf.rdev_major, buf.rdev_minor) as _;
    stat.st_size = buf.size as _;
    stat.st_blksize = buf.blksize as _;
    stat.st_blocks = buf.blocks as _;
    stat.st_atime = buf.atime.sec as _;
    stat.st_atime_nsec = buf.atime.nsec as _;
    stat.st_mtime = buf.mtime.sec as _;
    stat.st_mtime_nsec = buf.mtime.nsec as _;
    stat.st_ctime = buf.ctime.sec as _;
    stat.st_ctime_nsec = buf.ctime.nsec as _;
    let btime = (buf.mask & sys::STATX_BTIME != 0).then_some(buf.btime);
    Ok(FileAttr { stat, btime })
}

const AT_STATX_SYNC_AS_STAT: u32 = 0;

// all DirEntry's will have a reference to this struct
struct InnerReadDir {
    dirp: DirStream,
    root: PathBuf,
}

/// An open directory, read with `getdents64`.
struct DirStream(OwnedFd);

pub struct ReadDir {
    inner: Arc<InnerReadDir>,
    buf: Vec<u8>,
    /// the parsed part of `buf` ends at `pos`; `len` bytes are valid
    pos: usize,
    len: usize,
    end_of_stream: bool,
}

impl ReadDir {
    fn new(inner: InnerReadDir) -> Self {
        Self { inner: Arc::new(inner), buf: vec![0; 8192], pos: 0, len: 0, end_of_stream: false }
    }
}

fn debug_path_fd<'a, 'b>(
    fd: c_int,
    f: &'a mut fmt::Formatter<'b>,
    name: &str,
) -> fmt::DebugStruct<'a, 'b> {
    let mut b = f.debug_struct(name);

    fn get_mode(fd: c_int) -> Option<(bool, bool)> {
        let mode = sys::fcntl(fd, sys::F_GETFL, 0).ok()? as c_int;
        match mode & libc::O_ACCMODE {
            libc::O_RDONLY => Some((true, false)),
            libc::O_RDWR => Some((true, true)),
            libc::O_WRONLY => Some((false, true)),
            _ => None,
        }
    }

    b.field("fd", &fd);
    if let Some(path) = get_path_from_fd(fd) {
        b.field("path", &path);
    }
    if let Some((read, write)) = get_mode(fd) {
        b.field("read", &read).field("write", &write);
    }

    b
}

fn get_path_from_fd(fd: c_int) -> Option<PathBuf> {
    let mut p = PathBuf::from("/proc/self/fd");
    p.push(&fd.to_string());
    run_path_with_cstr(&p, &readlink).ok()
}

pub struct DirEntry {
    dir: Arc<InnerReadDir>,
    entry: dirent64_min,
    name: CString,
}

struct dirent64_min {
    d_ino: u64,
    d_type: u8,
}

#[derive(Clone)]
pub struct OpenOptions {
    // generic
    read: bool,
    write: bool,
    append: bool,
    truncate: bool,
    create: bool,
    create_new: bool,
    // system-specific
    custom_flags: i32,
    mode: mode_t,
}

#[derive(Clone, PartialEq, Eq)]
pub struct FilePermissions {
    mode: mode_t,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct FileTimes {
    accessed: Option<SystemTime>,
    modified: Option<SystemTime>,
}

#[derive(Copy, Clone, Eq)]
pub struct FileType {
    mode: mode_t,
}

impl PartialEq for FileType {
    fn eq(&self, other: &Self) -> bool {
        self.masked() == other.masked()
    }
}

impl core::hash::Hash for FileType {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.masked().hash(state);
    }
}

pub struct DirBuilder {
    mode: mode_t,
}

#[derive(Copy, Clone)]
struct Mode(mode_t);

impl FileAttr {
    pub fn size(&self) -> u64 {
        self.stat.st_size as u64
    }
    pub fn perm(&self) -> FilePermissions {
        FilePermissions { mode: (self.stat.st_mode as mode_t) }
    }

    pub fn file_type(&self) -> FileType {
        FileType { mode: self.stat.st_mode as mode_t }
    }

    pub fn modified(&self) -> io::Result<SystemTime> {
        SystemTime::new(self.stat.st_mtime as i64, self.stat.st_mtime_nsec as i64)
    }

    pub fn accessed(&self) -> io::Result<SystemTime> {
        SystemTime::new(self.stat.st_atime as i64, self.stat.st_atime_nsec as i64)
    }

    pub fn created(&self) -> io::Result<SystemTime> {
        match &self.btime {
            Some(t) => SystemTime::new(t.sec, t.nsec as i64),
            None => Err(io::const_error!(
                io::ErrorKind::Unsupported,
                "creation time is not available for the filesystem",
            )),
        }
    }
}

impl AsInner<stat64> for FileAttr {
    #[inline]
    fn as_inner(&self) -> &stat64 {
        &self.stat
    }
}

impl FilePermissions {
    pub fn readonly(&self) -> bool {
        // check if any class (owner, group, others) has write permission
        self.mode & 0o222 == 0
    }

    pub fn set_readonly(&mut self, readonly: bool) {
        if readonly {
            // remove write permission for all classes; equivalent to `chmod a-w <file>`
            self.mode &= !0o222;
        } else {
            // add write permission for all classes; equivalent to `chmod a+w <file>`
            self.mode |= 0o222;
        }
    }
    pub fn mode(&self) -> u32 {
        self.mode as u32
    }
}

impl FileTimes {
    pub fn set_accessed(&mut self, t: SystemTime) {
        self.accessed = Some(t);
    }

    pub fn set_modified(&mut self, t: SystemTime) {
        self.modified = Some(t);
    }
}

impl FileType {
    pub fn is_dir(&self) -> bool {
        self.is(libc::S_IFDIR)
    }
    pub fn is_file(&self) -> bool {
        self.is(libc::S_IFREG)
    }
    pub fn is_symlink(&self) -> bool {
        self.is(libc::S_IFLNK)
    }

    pub fn is(&self, mode: mode_t) -> bool {
        self.masked() == mode
    }

    fn masked(&self) -> mode_t {
        self.mode & libc::S_IFMT
    }
}

impl fmt::Debug for FileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let FileType { mode } = self;
        f.debug_struct("FileType").field("mode", &Mode(*mode)).finish()
    }
}

impl FromInner<u32> for FilePermissions {
    fn from_inner(mode: u32) -> FilePermissions {
        FilePermissions { mode: mode as mode_t }
    }
}

impl fmt::Debug for FilePermissions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let FilePermissions { mode } = self;
        f.debug_struct("FilePermissions").field("mode", &Mode(*mode)).finish()
    }
}

impl fmt::Debug for ReadDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // This will only be called from std::fs::ReadDir, which will add a "ReadDir()" frame.
        // Thus the result will be e g 'ReadDir("/home")'
        fmt::Debug::fmt(&*self.inner.root, f)
    }
}

impl Iterator for ReadDir {
    type Item = io::Result<DirEntry>;

    fn next(&mut self) -> Option<io::Result<DirEntry>> {
        loop {
            if self.end_of_stream {
                return None;
            }
            if self.pos == self.len {
                let fd = self.inner.dirp.0.as_raw_fd();
                match cvt(unsafe { sys::getdents64(fd, self.buf.as_mut_ptr(), self.buf.len()) }) {
                    Ok(0) => {
                        self.end_of_stream = true;
                        return None;
                    }
                    Ok(n) => (self.pos, self.len) = (0, n),
                    Err(e) => {
                        // the next call to next() should return None
                        self.end_of_stream = true;
                        return Some(Err(e));
                    }
                }
            }
            let mut it = dirent::Iter::new(&self.buf[self.pos..self.len]);
            let Some(e) = it.next() else {
                // a malformed record: drop the rest of this buffer
                self.pos = self.len;
                continue;
            };
            let parsed = self.len - self.pos - it.remaining();
            self.pos += parsed;
            if e.name == b"." || e.name == b".." {
                continue;
            }
            return Some(Ok(DirEntry {
                entry: dirent64_min { d_ino: e.ino, d_type: e.d_type },
                // a name from the kernel contains no NUL
                name: CString::new(e.name).unwrap(),
                dir: Arc::clone(&self.inner),
            }));
        }
    }
}

/// Aborts the process if a file descriptor is not open, if debug asserts are enabled
///
/// Many IO syscalls can't be fully trusted about EBADF error codes because those
/// might get bubbled up from a remote FUSE server rather than the file descriptor
/// in the current process being invalid.
///
/// So we check file flags instead which live on the file descriptor and not the underlying file.
/// The downside is that it costs an extra syscall, so we only do it for debug.
#[inline]
pub(crate) fn debug_assert_fd_is_open(fd: RawFd) {
    // this is similar to assert_unsafe_precondition!() but it doesn't require const
    if core::ub_checks::check_library_ub() {
        if let Err(sys::EBADF) = sys::fcntl(fd, sys::F_GETFD, 0) {
            rtabort!("IO Safety violation: owned file descriptor already closed");
        }
    }
}

impl DirEntry {
    pub fn path(&self) -> PathBuf {
        self.dir.root.join(self.file_name_os_str())
    }

    pub fn file_name(&self) -> OsString {
        self.file_name_os_str().to_os_string()
    }

    pub fn metadata(&self) -> io::Result<FileAttr> {
        statx(self.dir.dirp.0.as_raw_fd(), &self.name, sys::AT_SYMLINK_NOFOLLOW)
    }

    pub fn file_type(&self) -> io::Result<FileType> {
        match self.entry.d_type {
            dirent::DT_CHR => Ok(FileType { mode: libc::S_IFCHR }),
            dirent::DT_FIFO => Ok(FileType { mode: libc::S_IFIFO }),
            dirent::DT_LNK => Ok(FileType { mode: libc::S_IFLNK }),
            dirent::DT_REG => Ok(FileType { mode: libc::S_IFREG }),
            dirent::DT_SOCK => Ok(FileType { mode: libc::S_IFSOCK }),
            dirent::DT_DIR => Ok(FileType { mode: libc::S_IFDIR }),
            dirent::DT_BLK => Ok(FileType { mode: libc::S_IFBLK }),
            _ => self.metadata().map(|m| m.file_type()),
        }
    }

    pub fn ino(&self) -> u64 {
        self.entry.d_ino
    }

    pub fn file_name_os_str(&self) -> &OsStr {
        OsStr::from_bytes(self.name.as_bytes())
    }
}

impl OpenOptions {
    pub fn new() -> OpenOptions {
        OpenOptions {
            // generic
            read: false,
            write: false,
            append: false,
            truncate: false,
            create: false,
            create_new: false,
            // system-specific
            custom_flags: 0,
            mode: 0o666,
        }
    }

    pub fn read(&mut self, read: bool) {
        self.read = read;
    }
    pub fn write(&mut self, write: bool) {
        self.write = write;
    }
    pub fn append(&mut self, append: bool) {
        self.append = append;
    }
    pub fn truncate(&mut self, truncate: bool) {
        self.truncate = truncate;
    }
    pub fn create(&mut self, create: bool) {
        self.create = create;
    }
    pub fn create_new(&mut self, create_new: bool) {
        self.create_new = create_new;
    }

    pub fn custom_flags(&mut self, flags: i32) {
        self.custom_flags = flags;
    }
    pub fn mode(&mut self, mode: u32) {
        self.mode = mode as mode_t;
    }

    fn get_access_mode(&self) -> io::Result<c_int> {
        match (self.read, self.write, self.append) {
            (true, false, false) => Ok(libc::O_RDONLY),
            (false, true, false) => Ok(libc::O_WRONLY),
            (true, true, false) => Ok(libc::O_RDWR),
            (false, _, true) => Ok(libc::O_WRONLY | libc::O_APPEND),
            (true, _, true) => Ok(libc::O_RDWR | libc::O_APPEND),
            (false, false, false) => {
                // If no access mode is set, check if any creation flags are set
                // to provide a more descriptive error message
                if self.create || self.create_new || self.truncate {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "creating or truncating a file requires write or append access",
                    ))
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "must specify at least one of read, write, or append access",
                    ))
                }
            }
        }
    }

    fn get_creation_mode(&self) -> io::Result<c_int> {
        match (self.write, self.append) {
            (true, false) => {}
            (false, false) => {
                if self.truncate || self.create || self.create_new {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "creating or truncating a file requires write or append access",
                    ));
                }
            }
            (_, true) => {
                if self.truncate && !self.create_new {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "append and truncate cannot both be enabled",
                    ));
                }
            }
        }

        Ok(match (self.create, self.truncate, self.create_new) {
            (false, false, false) => 0,
            (true, false, false) => libc::O_CREAT,
            (false, true, false) => libc::O_TRUNC,
            (true, true, false) => libc::O_CREAT | libc::O_TRUNC,
            (_, _, true) => libc::O_CREAT | libc::O_EXCL,
        })
    }

    fn flags(&self, extra: c_int) -> io::Result<u32> {
        Ok((libc::O_CLOEXEC
            | self.get_access_mode()?
            | self.get_creation_mode()?
            | (self.custom_flags as c_int & !libc::O_ACCMODE)
            | extra) as u32)
    }
}

impl fmt::Debug for OpenOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let OpenOptions { read, write, append, truncate, create, create_new, custom_flags, mode } =
            self;
        f.debug_struct("OpenOptions")
            .field("read", read)
            .field("write", write)
            .field("append", append)
            .field("truncate", truncate)
            .field("create", create)
            .field("create_new", create_new)
            .field("custom_flags", custom_flags)
            .field("mode", &Mode(*mode))
            .finish()
    }
}

fn openat(dirfd: c_int, path: &CStr, flags: u32, mode: mode_t) -> io::Result<OwnedFd> {
    let fd = cvt_r(|| unsafe { sys::openat(dirfd, path.as_ptr().cast(), flags, mode) })?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

impl File {
    pub fn open(path: &Path, opts: &OpenOptions) -> io::Result<File> {
        run_path_with_cstr(path, &|path| File::open_c(path, opts))
    }

    pub fn open_c(path: &CStr, opts: &OpenOptions) -> io::Result<File> {
        let fd = openat(sys::AT_FDCWD, path, opts.flags(0)?, opts.mode)?;
        Ok(File(FileDesc::from_inner(fd)))
    }

    pub fn file_attr(&self) -> io::Result<FileAttr> {
        statx(self.as_raw_fd(), c"", sys::AT_EMPTY_PATH)
    }

    pub fn fsync(&self) -> io::Result<()> {
        cvt_r(|| sys::fsync(self.as_raw_fd())).map(drop)
    }

    pub fn datasync(&self) -> io::Result<()> {
        cvt_r(|| sys::fdatasync(self.as_raw_fd())).map(drop)
    }

    fn flock(&self, op: c_int) -> io::Result<()> {
        cvt(sys::flock(self.as_raw_fd(), op as u32)).map(drop)
    }

    fn try_flock(&self, op: c_int) -> Result<(), TryLockError> {
        match self.flock(op | libc::LOCK_NB) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Err(TryLockError::WouldBlock),
            Err(err) => Err(TryLockError::Error(err)),
        }
    }

    pub fn lock(&self) -> io::Result<()> {
        self.flock(libc::LOCK_EX)
    }

    pub fn lock_shared(&self) -> io::Result<()> {
        self.flock(libc::LOCK_SH)
    }

    pub fn try_lock(&self) -> Result<(), TryLockError> {
        self.try_flock(libc::LOCK_EX)
    }

    pub fn try_lock_shared(&self) -> Result<(), TryLockError> {
        self.try_flock(libc::LOCK_SH)
    }

    pub fn unlock(&self) -> io::Result<()> {
        self.flock(libc::LOCK_UN)
    }

    pub fn truncate(&self, size: u64) -> io::Result<()> {
        let size: i64 =
            size.try_into().map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        cvt_r(|| sys::ftruncate(self.as_raw_fd(), size as u64)).map(drop)
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }

    pub fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        self.0.read_vectored(bufs)
    }

    #[inline]
    pub fn is_read_vectored(&self) -> bool {
        self.0.is_read_vectored()
    }

    pub fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        self.0.read_at(buf, offset)
    }

    pub fn read_buf(&self, cursor: BorrowedCursor<'_, u8>) -> io::Result<()> {
        self.0.read_buf(cursor)
    }

    pub fn read_buf_at(&self, cursor: BorrowedCursor<'_, u8>, offset: u64) -> io::Result<()> {
        self.0.read_buf_at(cursor, offset)
    }

    pub fn read_vectored_at(&self, bufs: &mut [IoSliceMut<'_>], offset: u64) -> io::Result<usize> {
        self.0.read_vectored_at(bufs, offset)
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    pub fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.0.write_vectored(bufs)
    }

    #[inline]
    pub fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }

    pub fn write_at(&self, buf: &[u8], offset: u64) -> io::Result<usize> {
        self.0.write_at(buf, offset)
    }

    pub fn write_vectored_at(&self, bufs: &[IoSlice<'_>], offset: u64) -> io::Result<usize> {
        self.0.write_vectored_at(bufs, offset)
    }

    #[inline]
    pub fn flush(&self) -> io::Result<()> {
        Ok(())
    }

    pub fn seek(&self, pos: SeekFrom) -> io::Result<u64> {
        let (whence, pos) = match pos {
            // Casting to `i64` is fine, too large values will end up as
            // negative which will cause an error in `lseek`.
            SeekFrom::Start(off) => (libc::SEEK_SET, off as i64),
            SeekFrom::End(off) => (libc::SEEK_END, off),
            SeekFrom::Current(off) => (libc::SEEK_CUR, off),
        };
        let n = cvt(sys::lseek(self.as_raw_fd(), pos, whence as u32))?;
        Ok(n as u64)
    }

    pub fn size(&self) -> Option<io::Result<u64>> {
        match self.file_attr().map(|attr| attr.size()) {
            // Fall back to default implementation if the returned size is 0,
            // we might be in a proc mount.
            Ok(0) => None,
            result => Some(result),
        }
    }

    pub fn tell(&self) -> io::Result<u64> {
        self.seek(SeekFrom::Current(0))
    }

    pub fn duplicate(&self) -> io::Result<File> {
        self.0.duplicate().map(File)
    }

    pub fn set_permissions(&self, perm: FilePermissions) -> io::Result<()> {
        cvt_r(|| sys::fchmod(self.as_raw_fd(), perm.mode)).map(drop)
    }

    pub fn set_times(&self, times: FileTimes) -> io::Result<()> {
        let times = [file_time_to_timespec(times.accessed)?, file_time_to_timespec(times.modified)?];
        // utimensat with a null path is futimens
        cvt(unsafe { sys::utimensat(self.as_raw_fd(), ptr::null(), times.as_ptr(), 0) }).map(drop)
    }
}

fn file_time_to_timespec(time: Option<SystemTime>) -> io::Result<sys::Timespec> {
    match time {
        Some(time) if let Some(ts) = time.t.to_timespec() => {
            Ok(sys::Timespec { sec: ts.tv_sec, nsec: ts.tv_nsec })
        }
        Some(time) if time > crate::sys::time::UNIX_EPOCH => Err(io::const_error!(
            io::ErrorKind::InvalidInput,
            "timestamp is too large to set as a file time",
        )),
        Some(_) => Err(io::const_error!(
            io::ErrorKind::InvalidInput,
            "timestamp is too small to set as a file time",
        )),
        None => Ok(sys::Timespec { sec: 0, nsec: libc::UTIME_OMIT as _ }),
    }
}

impl DirBuilder {
    pub fn new() -> DirBuilder {
        DirBuilder { mode: 0o777 }
    }

    pub fn mkdir(&self, p: &Path) -> io::Result<()> {
        run_path_with_cstr(p, &|p| {
            cvt(unsafe { sys::mkdirat(sys::AT_FDCWD, p.as_ptr().cast(), self.mode) }).map(drop)
        })
    }

    pub fn set_mode(&mut self, mode: u32) {
        self.mode = mode as mode_t;
    }
}

impl fmt::Debug for DirBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let DirBuilder { mode } = self;
        f.debug_struct("DirBuilder").field("mode", &Mode(*mode)).finish()
    }
}

impl AsInner<FileDesc> for File {
    #[inline]
    fn as_inner(&self) -> &FileDesc {
        &self.0
    }
}

impl AsInnerMut<FileDesc> for File {
    #[inline]
    fn as_inner_mut(&mut self) -> &mut FileDesc {
        &mut self.0
    }
}

impl IntoInner<FileDesc> for File {
    fn into_inner(self) -> FileDesc {
        self.0
    }
}

impl FromInner<FileDesc> for File {
    fn from_inner(file_desc: FileDesc) -> Self {
        Self(file_desc)
    }
}

impl AsFd for File {
    #[inline]
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl AsRawFd for File {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl IntoRawFd for File {
    fn into_raw_fd(self) -> RawFd {
        self.0.into_raw_fd()
    }
}

impl FromRawFd for File {
    unsafe fn from_raw_fd(raw_fd: RawFd) -> Self {
        Self(unsafe { FromRawFd::from_raw_fd(raw_fd) })
    }
}

impl fmt::Debug for File {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fd = self.as_raw_fd();
        let mut b = debug_path_fd(fd, f, "File");
        b.finish()
    }
}

// Format in octal, followed by the mode format used in `ls -l`.
//
// Example:
//   0o100664 (-rw-rw-r--)
impl fmt::Debug for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self(mode) = *self;
        write!(f, "0o{mode:06o}")?;

        let entry_type = match mode & libc::S_IFMT {
            libc::S_IFDIR => 'd',
            libc::S_IFBLK => 'b',
            libc::S_IFCHR => 'c',
            libc::S_IFLNK => 'l',
            libc::S_IFIFO => 'p',
            libc::S_IFREG => '-',
            _ => return Ok(()),
        };

        f.write_str(" (")?;
        f.write_char(entry_type)?;

        // Owner permissions
        f.write_char(if mode & libc::S_IRUSR != 0 { 'r' } else { '-' })?;
        f.write_char(if mode & libc::S_IWUSR != 0 { 'w' } else { '-' })?;
        let owner_executable = mode & libc::S_IXUSR != 0;
        let setuid = mode as c_int & libc::S_ISUID as c_int != 0;
        f.write_char(match (owner_executable, setuid) {
            (true, true) => 's',  // executable and setuid
            (false, true) => 'S', // setuid
            (true, false) => 'x', // executable
            (false, false) => '-',
        })?;

        // Group permissions
        f.write_char(if mode & libc::S_IRGRP != 0 { 'r' } else { '-' })?;
        f.write_char(if mode & libc::S_IWGRP != 0 { 'w' } else { '-' })?;
        let group_executable = mode & libc::S_IXGRP != 0;
        let setgid = mode as c_int & libc::S_ISGID as c_int != 0;
        f.write_char(match (group_executable, setgid) {
            (true, true) => 's',  // executable and setgid
            (false, true) => 'S', // setgid
            (true, false) => 'x', // executable
            (false, false) => '-',
        })?;

        // Other permissions
        f.write_char(if mode & libc::S_IROTH != 0 { 'r' } else { '-' })?;
        f.write_char(if mode & libc::S_IWOTH != 0 { 'w' } else { '-' })?;
        let other_executable = mode & libc::S_IXOTH != 0;
        let sticky = mode as c_int & libc::S_ISVTX as c_int != 0;
        f.write_char(match (entry_type, other_executable, sticky) {
            ('d', true, true) => 't',  // searchable and restricted deletion
            ('d', false, true) => 'T', // restricted deletion
            (_, true, _) => 'x',       // executable
            (_, false, _) => '-',
        })?;

        f.write_char(')')
    }
}

fn opendir(dirfd: c_int, p: &CStr, nofollow: bool) -> io::Result<OwnedFd> {
    let mut flags = libc::O_CLOEXEC | libc::O_RDONLY | libc::O_DIRECTORY;
    if nofollow {
        flags |= libc::O_NOFOLLOW;
    }
    openat(dirfd, p, flags as u32, 0)
}

pub fn readdir(path: &Path) -> io::Result<ReadDir> {
    let fd = run_path_with_cstr(path, &|p| opendir(sys::AT_FDCWD, p, false))?;
    let root = path.to_path_buf();
    Ok(ReadDir::new(InnerReadDir { dirp: DirStream(fd), root }))
}

pub fn unlink(p: &CStr) -> io::Result<()> {
    cvt(unsafe { sys::unlinkat(sys::AT_FDCWD, p.as_ptr().cast(), 0) }).map(drop)
}

pub fn rename(old: &CStr, new: &CStr) -> io::Result<()> {
    cvt(unsafe {
        sys::renameat2(sys::AT_FDCWD, old.as_ptr().cast(), sys::AT_FDCWD, new.as_ptr().cast(), 0)
    })
    .map(drop)
}

pub fn set_perm(p: &CStr, perm: FilePermissions) -> io::Result<()> {
    cvt_r(|| unsafe { sys::fchmodat(sys::AT_FDCWD, p.as_ptr().cast(), perm.mode) }).map(drop)
}

pub fn set_perm_nofollow(p: &CStr, perm: FilePermissions) -> io::Result<()> {
    #[inline]
    /// Helper function for fallback open with `O_NOFOLLOW` + `fchmod` behavior
    fn open_and_set_permissions(p: &CStr, perm: FilePermissions) -> io::Result<()> {
        use crate::fs::{OpenOptions, Permissions};
        use crate::os::unix::fs::OpenOptionsExt;

        let mut options = OpenOptions::new();
        options.read(true);
        options.custom_flags(libc::O_NOFOLLOW);

        // SAFETY: Since this function is called with `with_native_path`
        // and that successfully converted the `&Path` to a `CString`,
        // it should be safe to convert the `&CStr` back to a `Path`.
        let os_str = unsafe { OsStr::from_encoded_bytes_unchecked(p.to_bytes()) };
        options.open(Path::new(os_str))?.set_permissions(Permissions::from_inner(perm))
    }

    // fchmodat2 (Linux 6.6) takes AT_SYMLINK_NOFOLLOW; before it, fall back to
    // open + fchmod, which fails with ELOOP on a symlink
    let res = cvt_r(|| unsafe {
        sys::fchmodat2(sys::AT_FDCWD, p.as_ptr().cast(), perm.mode, sys::AT_SYMLINK_NOFOLLOW)
    })
    .map(drop);
    match res {
        Err(err) if err.raw_os_error() == Some(libc::ENOSYS) => match open_and_set_permissions(p, perm) {
            Err(e) if e.kind() == io::ErrorKind::FilesystemLoop => {
                // keep the error consistent with fchmodat2 on a symlink
                Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
            }
            r => r,
        },
        r => r,
    }
}

pub fn rmdir(p: &CStr) -> io::Result<()> {
    cvt(unsafe { sys::unlinkat(sys::AT_FDCWD, p.as_ptr().cast(), sys::AT_REMOVEDIR) }).map(drop)
}

pub fn readlink(c_path: &CStr) -> io::Result<PathBuf> {
    let p = c_path.as_ptr().cast();

    let mut buf = Vec::with_capacity(256);

    loop {
        let buf_read =
            cvt(unsafe { sys::readlinkat(sys::AT_FDCWD, p, buf.as_mut_ptr(), buf.capacity()) })?;

        unsafe {
            buf.set_len(buf_read);
        }

        if buf_read != buf.capacity() {
            buf.shrink_to_fit();

            return Ok(PathBuf::from(OsString::from_vec(buf)));
        }

        // Trigger the internal buffer resizing logic of `Vec` by requiring
        // more space than the current capacity. The length is guaranteed to be
        // the same as the capacity due to the if statement above.
        buf.reserve(1);
    }
}

pub fn symlink(original: &CStr, link: &CStr) -> io::Result<()> {
    cvt(unsafe { sys::symlinkat(original.as_ptr().cast(), sys::AT_FDCWD, link.as_ptr().cast()) })
        .map(drop)
}

pub fn link(original: &CStr, link: &CStr) -> io::Result<()> {
    cvt(unsafe {
        sys::linkat(sys::AT_FDCWD, original.as_ptr().cast(), sys::AT_FDCWD, link.as_ptr().cast(), 0)
    })
    .map(drop)
}

pub fn stat(p: &CStr) -> io::Result<FileAttr> {
    statx(sys::AT_FDCWD, p, 0)
}

pub fn lstat(p: &CStr) -> io::Result<FileAttr> {
    statx(sys::AT_FDCWD, p, sys::AT_SYMLINK_NOFOLLOW)
}

/// `realpath` in userspace, the way glibc (gnulib) does it: walk the path a
/// component at a time, with `readlink` telling symlinks (whose targets are
/// spliced in front of what is left) from everything else. It needs no
/// `/proc`.
pub fn canonicalize(path: &CStr) -> io::Result<PathBuf> {
    // Linux's own limit on symlinks per lookup (and glibc's)
    const MAX_LINKS: u32 = 40;

    let path = path.to_bytes();
    if path.is_empty() {
        return Err(io::Error::from_raw_os_error(libc::ENOENT));
    }
    // what is resolved so far: absolute, symlink-free, and with no trailing
    // slash unless it is "/"
    let mut out = if path[0] == b'/' {
        vec![b'/']
    } else {
        let cwd = crate::sys::paths::getcwd()?.into_os_string().into_vec();
        // the kernel's "(unreachable)/..." for a cwd outside our root
        if cwd.first() != Some(&b'/') {
            return Err(io::Error::from_raw_os_error(libc::ENOENT));
        }
        cwd
    };
    // what is still to resolve
    let mut rest = path.to_vec();
    let mut pos = 0;
    let mut links = 0;

    loop {
        while rest.get(pos) == Some(&b'/') {
            pos += 1;
        }
        if pos == rest.len() {
            break;
        }
        let end = rest[pos..].iter().position(|&b| b == b'/').map_or(rest.len(), |i| pos + i);
        match &rest[pos..end] {
            b"." => {}
            b".." => {
                // `out` has no symlinks left in it, so ".." is lexical here
                let parent = out.iter().rposition(|&b| b == b'/').unwrap_or(0);
                out.truncate(parent.max(1));
            }
            name => {
                let parent_len = out.len();
                if out.len() > 1 {
                    out.push(b'/');
                }
                out.extend_from_slice(name);
                out.push(0);
                let r = readlink(CStr::from_bytes_with_nul(&out).unwrap());
                out.pop();
                match r {
                    Ok(target) => {
                        links += 1;
                        if links > MAX_LINKS {
                            return Err(io::Error::from_raw_os_error(libc::ELOOP));
                        }
                        let mut target = target.into_os_string().into_vec();
                        if target.first() == Some(&b'/') {
                            out.truncate(1);
                        } else {
                            out.truncate(parent_len);
                        }
                        target.extend_from_slice(&rest[end..]);
                        rest = target;
                        pos = 0;
                        continue;
                    }
                    // not a symlink: then it must be a directory if a
                    // trailing "/", "/." or a "/.." follows (a further
                    // name would fail its own lookup with ENOTDIR)
                    Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {
                        if suffix_requires_dir(&rest[end..]) {
                            out.push(0);
                            let attr = statx(sys::AT_FDCWD, CStr::from_bytes_with_nul(&out).unwrap(), 0);
                            out.pop();
                            if !attr?.file_type().is_dir() {
                                return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
                            }
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        pos = end;
    }
    Ok(PathBuf::from(OsString::from_vec(out)))
}

/// Whether what follows a component only makes sense for a directory: a
/// trailing slash, or ".." coming next (perhaps after some "."s).
fn suffix_requires_dir(suffix: &[u8]) -> bool {
    if suffix.is_empty() {
        return false;
    }
    for name in suffix.split(|&b| b == b'/').filter(|n| !n.is_empty()) {
        match name {
            b"." => {}
            b".." => return true,
            _ => return false,
        }
    }
    true
}

fn open_from(from: &Path) -> io::Result<(crate::fs::File, crate::fs::Metadata)> {
    use crate::fs::File;
    use crate::sys::fs::common::NOT_FILE_ERROR;

    let reader = File::open(from)?;
    let metadata = reader.metadata()?;
    if !metadata.is_file() {
        return Err(NOT_FILE_ERROR);
    }
    Ok((reader, metadata))
}

fn set_times_impl(p: &CStr, times: FileTimes, follow_symlinks: bool) -> io::Result<()> {
    let flags = if follow_symlinks { 0 } else { sys::AT_SYMLINK_NOFOLLOW };
    let times = [file_time_to_timespec(times.accessed)?, file_time_to_timespec(times.modified)?];
    cvt(unsafe { sys::utimensat(sys::AT_FDCWD, p.as_ptr().cast(), times.as_ptr(), flags) })
        .map(drop)
}

#[inline(always)]
pub fn set_times(p: &CStr, times: FileTimes) -> io::Result<()> {
    set_times_impl(p, times, true)
}

#[inline(always)]
pub fn set_times_nofollow(p: &CStr, times: FileTimes) -> io::Result<()> {
    set_times_impl(p, times, false)
}

fn open_to_and_set_permissions(
    to: &Path,
    reader_metadata: &crate::fs::Metadata,
) -> io::Result<(crate::fs::File, crate::fs::Metadata)> {
    use crate::fs::OpenOptions;
    use crate::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let perm = reader_metadata.permissions();
    let writer = OpenOptions::new()
        // create the file with the correct mode right away
        .mode(perm.mode())
        .write(true)
        .create(true)
        .truncate(true)
        .open(to)?;
    let writer_metadata = writer.metadata()?;
    if writer_metadata.is_file() {
        // Set the correct file permissions, in case the file already existed.
        // Don't set the permissions on already existing non-files like
        // pipes/FIFOs or device nodes.
        writer.set_permissions(perm)?;
    }
    Ok((writer, writer_metadata))
}

mod cfm {
    use crate::fs::{File, Metadata};
    use crate::io::{BorrowedCursor, IoSlice, IoSliceMut, Read, Result, Write};

    #[allow(dead_code)]
    pub struct CachedFileMetadata(pub File, pub Metadata);

    impl Read for CachedFileMetadata {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            self.0.read(buf)
        }
        fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> Result<usize> {
            self.0.read_vectored(bufs)
        }
        fn read_buf(&mut self, cursor: BorrowedCursor<'_, u8>) -> Result<()> {
            self.0.read_buf(cursor)
        }
        #[inline]
        fn is_read_vectored(&self) -> bool {
            self.0.is_read_vectored()
        }
        fn read_to_end(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
            self.0.read_to_end(buf)
        }
        fn read_to_string(&mut self, buf: &mut String) -> Result<usize> {
            self.0.read_to_string(buf)
        }
    }
    impl Write for CachedFileMetadata {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            self.0.write(buf)
        }
        fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> Result<usize> {
            self.0.write_vectored(bufs)
        }
        #[inline]
        fn is_write_vectored(&self) -> bool {
            self.0.is_write_vectored()
        }
        #[inline]
        fn flush(&mut self) -> Result<()> {
            self.0.flush()
        }
    }
}
pub(in crate::sys) use cfm::CachedFileMetadata;

pub fn copy(from: &Path, to: &Path) -> io::Result<u64> {
    let (reader, reader_metadata) = open_from(from)?;
    let (writer, writer_metadata) = open_to_and_set_permissions(to, &reader_metadata)?;

    io::copy(
        &mut cfm::CachedFileMetadata(reader, reader_metadata),
        &mut cfm::CachedFileMetadata(writer, writer_metadata),
    )
}

pub fn chown(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
    run_path_with_cstr(path, &|path| {
        cvt(unsafe { sys::fchownat(sys::AT_FDCWD, path.as_ptr().cast(), uid, gid, 0) }).map(drop)
    })
}

pub fn fchown(fd: c_int, uid: u32, gid: u32) -> io::Result<()> {
    cvt(sys::fchown(fd, uid, gid)).map(drop)
}

pub fn lchown(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
    run_path_with_cstr(path, &|path| {
        cvt(unsafe {
            sys::fchownat(sys::AT_FDCWD, path.as_ptr().cast(), uid, gid, sys::AT_SYMLINK_NOFOLLOW)
        })
        .map(drop)
    })
}

pub fn chroot(dir: &Path) -> io::Result<()> {
    run_path_with_cstr(dir, &|dir| cvt(unsafe { sys::chroot(dir.as_ptr().cast()) }).map(drop))
}

pub fn mkfifo(path: &Path, mode: u32) -> io::Result<()> {
    run_path_with_cstr(path, &|path| {
        cvt(unsafe { sys::mknodat(sys::AT_FDCWD, path.as_ptr().cast(), libc::S_IFIFO | mode, 0) })
            .map(drop)
    })
}

pub use remove_dir_impl::remove_dir_all;

// Using openat(), unlinkat() and getdents64() on the directory fds
mod remove_dir_impl {
    use super::{
        AsRawFd, DirEntry, DirStream, InnerReadDir, OwnedFd, RawFd, ReadDir, dirent, lstat,
        opendir, sys,
    };
    use crate::ffi::CStr;
    use crate::io;
    use crate::path::{Path, PathBuf};
    use crate::sys::cvt;
    use crate::sys::helpers::{ignore_notfound, run_path_with_cstr};

    pub fn openat_nofollow_dironly(parent_fd: Option<RawFd>, p: &CStr) -> io::Result<OwnedFd> {
        opendir(parent_fd.unwrap_or(sys::AT_FDCWD), p, true)
    }

    fn fdreaddir(dir_fd: OwnedFd) -> (ReadDir, RawFd) {
        let fd = dir_fd.as_raw_fd();
        // a valid root is not needed because we do not call any functions involving the full path
        // of the `DirEntry`s.
        let dummy_root = PathBuf::new();
        let inner = InnerReadDir { dirp: DirStream(dir_fd), root: dummy_root };
        (ReadDir::new(inner), fd)
    }

    fn is_dir(ent: &DirEntry) -> Option<bool> {
        match ent.entry.d_type {
            dirent::DT_UNKNOWN => None,
            dirent::DT_DIR => Some(true),
            _ => Some(false),
        }
    }

    fn is_enoent(result: &io::Result<()>) -> bool {
        if let Err(err) = result
            && matches!(err.raw_os_error(), Some(libc::ENOENT))
        {
            true
        } else {
            false
        }
    }

    fn unlinkat(fd: RawFd, path: &CStr, flags: u32) -> io::Result<()> {
        cvt(unsafe { sys::unlinkat(fd, path.as_ptr().cast(), flags) }).map(drop)
    }

    fn remove_dir_all_recursive(parent_fd: Option<RawFd>, path: &CStr) -> io::Result<()> {
        // try opening as directory
        let fd = match openat_nofollow_dironly(parent_fd, path) {
            Err(err) if matches!(err.raw_os_error(), Some(libc::ENOTDIR | libc::ELOOP)) => {
                // not a directory - don't traverse further
                // (for symlinks, older Linux kernels may return ELOOP instead of ENOTDIR)
                return match parent_fd {
                    // unlink...
                    Some(parent_fd) => unlinkat(parent_fd, path, 0),
                    // ...unless this was supposed to be the deletion root directory
                    None => Err(err),
                };
            }
            result => result?,
        };

        // the ReadDir owns the fd from here on
        let (dir, fd) = fdreaddir(fd);

        for child in dir {
            let child = child?;
            // we need an inner try block, because if one of these
            // directories has already been deleted, then we need to
            // continue the loop, not return ok.
            let result: io::Result<()> = try {
                match is_dir(&child) {
                    Some(true) => {
                        remove_dir_all_recursive(Some(fd), &child.name)?;
                    }
                    Some(false) => {
                        unlinkat(fd, &child.name, 0)?;
                    }
                    None => {
                        // POSIX specifies that calling unlink()/unlinkat(..., 0) on a directory can succeed
                        // if the process has the appropriate privileges. This however can causing orphaned
                        // directories requiring an fsck e.g. on Solaris and Illumos. So we try recursing
                        // into it first instead of trying to unlink() it.
                        remove_dir_all_recursive(Some(fd), &child.name)?;
                    }
                }
            };
            if result.is_err() && !is_enoent(&result) {
                return result;
            }
        }

        // unlink the directory after removing its contents
        ignore_notfound(unlinkat(parent_fd.unwrap_or(sys::AT_FDCWD), path, sys::AT_REMOVEDIR))?;
        Ok(())
    }

    fn remove_dir_all_modern(p: &CStr) -> io::Result<()> {
        // We cannot just call remove_dir_all_recursive() here because that would not delete a passed
        // symlink. No need to worry about races, because remove_dir_all_recursive() does not recurse
        // into symlinks.
        let attr = lstat(p)?;
        if attr.file_type().is_symlink() {
            super::unlink(p)
        } else {
            remove_dir_all_recursive(None, p)
        }
    }

    pub fn remove_dir_all(p: &Path) -> io::Result<()> {
        run_path_with_cstr(p, &remove_dir_all_modern)
    }
}

pub struct Dir(OwnedFd);

impl Dir {
    pub fn open(path: &Path, opts: &OpenOptions) -> io::Result<Self> {
        run_path_with_cstr(path, &|path| {
            openat(sys::AT_FDCWD, path, opts.flags(libc::O_DIRECTORY)?, opts.mode).map(Self)
        })
    }

    pub fn open_for_traversal(path: &Path) -> io::Result<Self> {
        let flags = libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_PATH;
        run_path_with_cstr(path, &|path| openat(sys::AT_FDCWD, path, flags as u32, 0).map(Self))
    }

    pub fn open_file(&self, path: &Path, opts: &OpenOptions) -> io::Result<File> {
        run_path_with_cstr(path, &|path| {
            openat(self.0.as_raw_fd(), path, opts.flags(0)?, opts.mode)
        })
        .map(FileDesc::from_inner)
        .map(File)
    }

    pub fn metadata(&self) -> io::Result<FileAttr> {
        statx(self.0.as_raw_fd(), c"", sys::AT_EMPTY_PATH)
    }

    pub fn remove_file(&self, path: &Path) -> io::Result<()> {
        run_path_with_cstr(path, &|path| self.remove_c(path, false))
    }

    pub fn rename(&self, from: &Path, to_dir: &Self, to: &Path) -> io::Result<()> {
        run_path_with_cstr(from, &|from| {
            run_path_with_cstr(to, &|to| {
                cvt(unsafe {
                    sys::renameat2(
                        self.0.as_raw_fd(),
                        from.as_ptr().cast(),
                        to_dir.0.as_raw_fd(),
                        to.as_ptr().cast(),
                        0,
                    )
                })
                .map(drop)
            })
        })
    }

    pub fn open_dir(&self, path: &Path, opts: &OpenOptions) -> io::Result<Self> {
        run_path_with_cstr(path, &|path| {
            openat(self.0.as_raw_fd(), path, opts.flags(libc::O_DIRECTORY)?, opts.mode)
        })
        .map(Self)
    }

    pub fn create_dir(&self, path: &Path) -> io::Result<()> {
        run_path_with_cstr(path, &|path| {
            cvt(unsafe { sys::mkdirat(self.0.as_raw_fd(), path.as_ptr().cast(), 0o777) }).map(drop)
        })
    }

    pub fn remove_dir(&self, path: &Path) -> io::Result<()> {
        run_path_with_cstr(path, &|path| self.remove_c(path, true))
    }

    fn remove_c(&self, path: &CStr, remove_dir: bool) -> io::Result<()> {
        let flags = if remove_dir { sys::AT_REMOVEDIR } else { 0 };
        cvt(unsafe { sys::unlinkat(self.0.as_raw_fd(), path.as_ptr().cast(), flags) }).map(drop)
    }
}

impl fmt::Debug for Dir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fd = self.0.as_raw_fd();
        let mut b = debug_path_fd(fd, f, "Dir");
        b.finish()
    }
}

#[unstable(feature = "dirfd", issue = "120426")]
impl AsRawFd for fs::Dir {
    fn as_raw_fd(&self) -> RawFd {
        self.as_inner().0.as_raw_fd()
    }
}

#[unstable(feature = "dirfd", issue = "120426")]
impl IntoRawFd for fs::Dir {
    fn into_raw_fd(self) -> RawFd {
        self.into_inner().0.into_raw_fd()
    }
}

#[unstable(feature = "dirfd", issue = "120426")]
impl FromRawFd for fs::Dir {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Self::from_inner(Dir(unsafe { FromRawFd::from_raw_fd(fd) }))
    }
}

#[unstable(feature = "dirfd", issue = "120426")]
impl AsFd for fs::Dir {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.as_inner().0.as_fd()
    }
}

#[unstable(feature = "dirfd", issue = "120426")]
impl From<fs::Dir> for OwnedFd {
    fn from(value: fs::Dir) -> Self {
        value.into_inner().0
    }
}

#[unstable(feature = "dirfd", issue = "120426")]
impl From<OwnedFd> for fs::Dir {
    fn from(value: OwnedFd) -> Self {
        Self::from_inner(Dir(value))
    }
}
