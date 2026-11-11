//! Typed syscall wrappers. Every wrapper returns `Err(errno)` on failure.


use crate::arch::syscall6;
use crate::arch::nr;

pub type SysResult<T = usize> = Result<T, i32>;

#[inline(always)]
fn check(ret: usize) -> SysResult {
    // the kernel returns -4095..=-1 for errors
    if ret > (-4096isize) as usize { Err(-(ret as isize) as i32) } else { Ok(ret) }
}

#[inline(always)]
pub unsafe fn syscall(n: usize, args: [usize; 6]) -> SysResult {
    check(unsafe { syscall6(n, args[0], args[1], args[2], args[3], args[4], args[5]) })
}

macro_rules! sc {
    ($n:expr) => { syscall($n, [0; 6]) };
    ($n:expr, $a:expr) => { syscall($n, [$a as usize, 0, 0, 0, 0, 0]) };
    ($n:expr, $a:expr, $b:expr) => { syscall($n, [$a as usize, $b as usize, 0, 0, 0, 0]) };
    ($n:expr, $a:expr, $b:expr, $c:expr) => { syscall($n, [$a as usize, $b as usize, $c as usize, 0, 0, 0]) };
    ($n:expr, $a:expr, $b:expr, $c:expr, $d:expr) => { syscall($n, [$a as usize, $b as usize, $c as usize, $d as usize, 0, 0]) };
    ($n:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr) => { syscall($n, [$a as usize, $b as usize, $c as usize, $d as usize, $e as usize, 0]) };
    ($n:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr) => { syscall($n, [$a as usize, $b as usize, $c as usize, $d as usize, $e as usize, $f as usize]) };
}

// ---- errno ----
pub const EPERM: i32 = 1;
pub const ENOENT: i32 = 2;
pub const EINTR: i32 = 4;
pub const EIO: i32 = 5;
pub const EBADF: i32 = 9;
pub const ECHILD: i32 = 10;
pub const E2BIG: i32 = 7;
pub const EAGAIN: i32 = 11;
pub const ENOMEM: i32 = 12;
pub const EACCES: i32 = 13;
pub const EBUSY: i32 = 16;
pub const EEXIST: i32 = 17;
pub const EXDEV: i32 = 18;
pub const ENOTDIR: i32 = 20;
pub const EISDIR: i32 = 21;
pub const EINVAL: i32 = 22;
pub const ETXTBSY: i32 = 26;
pub const EFBIG: i32 = 27;
pub const ENOSPC: i32 = 28;
pub const ESPIPE: i32 = 29;
pub const EROFS: i32 = 30;
pub const EMLINK: i32 = 31;
pub const EPIPE: i32 = 32;
pub const ERANGE: i32 = 34;
pub const EDEADLK: i32 = 35;
pub const ENAMETOOLONG: i32 = 36;
pub const ENOSYS: i32 = 38;
pub const ENOTEMPTY: i32 = 39;
pub const ELOOP: i32 = 40;
pub const EOVERFLOW: i32 = 75;
pub const EADDRINUSE: i32 = 98;
pub const EADDRNOTAVAIL: i32 = 99;
pub const ENETDOWN: i32 = 100;
pub const ENETUNREACH: i32 = 101;
pub const ECONNABORTED: i32 = 103;
pub const ECONNRESET: i32 = 104;
pub const ENOTCONN: i32 = 107;
pub const ETIMEDOUT: i32 = 110;
pub const ECONNREFUSED: i32 = 111;
pub const EHOSTUNREACH: i32 = 113;
pub const EINPROGRESS: i32 = 115;
pub const ESRCH: i32 = 3;
pub const ENOEXEC: i32 = 8;
pub const EFAULT: i32 = 14;
pub const ENODEV: i32 = 19;
pub const EMFILE: i32 = 24;
pub const ENOTTY: i32 = 25;
pub const EDOM: i32 = 33;
pub const ENOTSOCK: i32 = 88;
pub const EOPNOTSUPP: i32 = 95;
pub const EAFNOSUPPORT: i32 = 97;
pub const EISCONN: i32 = 106;
pub const EALREADY: i32 = 114;
pub const ESTALE: i32 = 116;
pub const EDQUOT: i32 = 122;
pub const EWOULDBLOCK: i32 = EAGAIN;

// ---- open / at ----
pub const AT_FDCWD: i32 = -100;
pub const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
pub const AT_REMOVEDIR: u32 = 0x200;
pub const AT_EMPTY_PATH: u32 = 0x1000;
pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 1;
pub const O_RDWR: u32 = 2;
pub const O_CREAT: u32 = 0o100;
pub const O_EXCL: u32 = 0o200;
pub const O_NOCTTY: u32 = 0o400;
pub const O_TRUNC: u32 = 0o1000;
pub const O_APPEND: u32 = 0o2000;
pub const O_NONBLOCK: u32 = 0o4000;
#[cfg(target_arch = "x86_64")]
pub const O_DIRECTORY: u32 = 0o200000;
#[cfg(target_arch = "aarch64")]
pub const O_DIRECTORY: u32 = 0o40000;
#[cfg(target_arch = "x86_64")]
pub const O_NOFOLLOW: u32 = 0o400000;
#[cfg(target_arch = "aarch64")]
pub const O_NOFOLLOW: u32 = 0o100000;
pub const O_CLOEXEC: u32 = 0o2000000;
pub const O_PATH: u32 = 0o10000000;
pub const X_OK: u32 = 1;

pub const F_DUPFD_CLOEXEC: u32 = 1030;
pub const F_GETFD: u32 = 1;
pub const F_SETFD: u32 = 2;
pub const F_GETFL: u32 = 3;
pub const F_SETFL: u32 = 4;
pub const FD_CLOEXEC: usize = 1;

pub const S_IFMT: u32 = 0o170000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFIFO: u32 = 0o010000;
pub const S_IFSOCK: u32 = 0o140000;
pub const S_IFCHR: u32 = 0o020000;
pub const S_IFBLK: u32 = 0o060000;

// ---- mmap ----
pub const PROT_NONE: usize = 0;
pub const PROT_READ: usize = 1;
pub const PROT_WRITE: usize = 2;
pub const MAP_PRIVATE: usize = 0x02;
pub const MAP_ANONYMOUS: usize = 0x20;
pub const MAP_STACK: usize = 0x20000;
pub const MAP_NORESERVE: usize = 0x4000;
pub const PAGE_SIZE: usize = 4096;

// ---- clocks ----
pub const CLOCK_REALTIME: usize = 0;
pub const CLOCK_MONOTONIC: usize = 1;

// ---- signals ----
pub const SIGABRT: usize = 6;
pub const SIGKILL: usize = 9;
pub const SIGPIPE: usize = 13;
pub const SIGCHLD: usize = 17;
pub const SIGSEGV: usize = 11;
pub const SIGBUS: usize = 7;
pub const SIG_IGN: usize = 1;
pub const SIG_DFL: usize = 0;
pub const SIG_UNBLOCK: usize = 1;
pub const SIG_SETMASK: usize = 2;
pub const SA_SIGINFO: usize = 4;
pub const SA_ONSTACK: usize = 0x0800_0000;
pub const SA_RESTORER: usize = 0x0400_0000;
pub const SS_DISABLE: i32 = 2;

// ---- clone ----
pub const CLONE_VM: usize = 0x100;
pub const CLONE_VFORK: usize = 0x4000;
pub const CLONE_FS: usize = 0x200;
pub const CLONE_FILES: usize = 0x400;
pub const CLONE_SIGHAND: usize = 0x800;
pub const CLONE_THREAD: usize = 0x10000;
pub const CLONE_SYSVSEM: usize = 0x40000;
pub const CLONE_SETTLS: usize = 0x80000;
pub const CLONE_PARENT_SETTID: usize = 0x100000;
pub const CLONE_CHILD_CLEARTID: usize = 0x200000;

// ---- sockets ----
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;
pub const SOCK_STREAM: u32 = 1;
pub const SOCK_DGRAM: u32 = 2;
pub const SOCK_CLOEXEC: u32 = O_CLOEXEC;
pub const SOCK_NONBLOCK: u32 = O_NONBLOCK;
pub const SOL_SOCKET: u32 = 1;
pub const SO_REUSEADDR: u32 = 2;
pub const SO_ERROR: u32 = 4;
pub const SO_BROADCAST: u32 = 6;
pub const SO_RCVTIMEO: u32 = 20;
pub const SO_SNDTIMEO: u32 = 21;
pub const IPPROTO_IP: u32 = 0;
pub const IPPROTO_TCP: u32 = 6;
pub const IPPROTO_IPV6: u32 = 41;
pub const IP_TTL: u32 = 2;
pub const TCP_NODELAY: u32 = 1;
pub const IPV6_V6ONLY: u32 = 26;
pub const MSG_PEEK: u32 = 2;
pub const MSG_NOSIGNAL: u32 = 0x4000;
pub const SHUT_RD: u32 = 0;
pub const SHUT_WR: u32 = 1;
pub const SHUT_RDWR: u32 = 2;

pub const POLLIN: i16 = 1;
pub const POLLOUT: i16 = 4;
pub const POLLERR: i16 = 8;
pub const POLLHUP: i16 = 16;

pub const FUTEX_WAIT: usize = 0;
pub const FUTEX_WAKE: usize = 1;
pub const FUTEX_PRIVATE: usize = 128;
pub const FUTEX_WAIT_BITSET: usize = 9;

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct Timespec {
    pub sec: i64,
    pub nsec: i64,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct StatxTimestamp {
    pub sec: i64,
    pub nsec: u32,
    pub reserved: i32,
}

/// `struct statx`: the same layout on every architecture.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct Statx {
    pub mask: u32,
    pub blksize: u32,
    pub attributes: u64,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub mode: u16,
    pub spare0: u16,
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub attributes_mask: u64,
    pub atime: StatxTimestamp,
    pub btime: StatxTimestamp,
    pub ctime: StatxTimestamp,
    pub mtime: StatxTimestamp,
    pub rdev_major: u32,
    pub rdev_minor: u32,
    pub dev_major: u32,
    pub dev_minor: u32,
    pub spare: [u64; 14],
}
pub const STATX_BASIC_STATS: u32 = 0x7ff;
pub const STATX_BTIME: u32 = 0x800;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct IoVec {
    pub base: *const u8,
    pub len: usize,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PollFd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

// ---- wrappers ----

pub unsafe fn read(fd: i32, buf: *mut u8, len: usize) -> SysResult {
    unsafe { sc!(nr::READ, fd, buf, len) }
}
pub unsafe fn write(fd: i32, buf: *const u8, len: usize) -> SysResult {
    unsafe { sc!(nr::WRITE, fd, buf, len) }
}
pub unsafe fn pread(fd: i32, buf: *mut u8, len: usize, off: u64) -> SysResult {
    unsafe { sc!(nr::PREAD64, fd, buf, len, off) }
}
pub unsafe fn pwrite(fd: i32, buf: *const u8, len: usize, off: u64) -> SysResult {
    unsafe { sc!(nr::PWRITE64, fd, buf, len, off) }
}
pub fn close(fd: i32) -> SysResult {
    unsafe { sc!(nr::CLOSE, fd) }
}
pub fn lseek(fd: i32, off: i64, whence: u32) -> SysResult {
    unsafe { sc!(nr::LSEEK, fd, off, whence) }
}
pub unsafe fn openat(dirfd: i32, path: *const u8, flags: u32, mode: u32) -> SysResult<i32> {
    unsafe { sc!(nr::OPENAT, dirfd, path, flags, mode).map(|f| f as i32) }
}
pub fn fcntl(fd: i32, cmd: u32, arg: usize) -> SysResult {
    unsafe { sc!(nr::FCNTL, fd, cmd, arg) }
}
pub fn dup3(old: i32, new: i32, flags: u32) -> SysResult<i32> {
    unsafe { sc!(nr::DUP3, old, new, flags).map(|f| f as i32) }
}
pub fn pipe2(flags: u32) -> SysResult<[i32; 2]> {
    let mut fds = [0i32; 2];
    unsafe { sc!(nr::PIPE2, fds.as_mut_ptr(), flags)? };
    Ok(fds)
}
pub fn fsync(fd: i32) -> SysResult {
    unsafe { sc!(nr::FSYNC, fd) }
}
pub fn fdatasync(fd: i32) -> SysResult {
    unsafe { sc!(nr::FDATASYNC, fd) }
}
pub fn ftruncate(fd: i32, len: u64) -> SysResult {
    unsafe { sc!(nr::FTRUNCATE, fd, len) }
}
pub fn fchmod(fd: i32, mode: u32) -> SysResult {
    unsafe { sc!(nr::FCHMOD, fd, mode) }
}
pub unsafe fn fchmodat(dirfd: i32, path: *const u8, mode: u32) -> SysResult {
    unsafe { sc!(nr::FCHMODAT, dirfd, path, mode) }
}
pub unsafe fn statx(dirfd: i32, path: *const u8, flags: u32, mask: u32, buf: *mut Statx) -> SysResult {
    unsafe { sc!(nr::STATX, dirfd, path, flags, mask, buf) }
}
pub unsafe fn mkdirat(dirfd: i32, path: *const u8, mode: u32) -> SysResult {
    unsafe { sc!(nr::MKDIRAT, dirfd, path, mode) }
}
pub unsafe fn unlinkat(dirfd: i32, path: *const u8, flags: u32) -> SysResult {
    unsafe { sc!(nr::UNLINKAT, dirfd, path, flags) }
}
pub unsafe fn renameat2(odir: i32, old: *const u8, ndir: i32, new: *const u8, flags: u32) -> SysResult {
    unsafe { sc!(nr::RENAMEAT2, odir, old, ndir, new, flags) }
}
pub unsafe fn linkat(odir: i32, old: *const u8, ndir: i32, new: *const u8, flags: u32) -> SysResult {
    unsafe { sc!(nr::LINKAT, odir, old, ndir, new, flags) }
}
pub unsafe fn symlinkat(target: *const u8, dirfd: i32, link: *const u8) -> SysResult {
    unsafe { sc!(nr::SYMLINKAT, target, dirfd, link) }
}
pub unsafe fn readlinkat(dirfd: i32, path: *const u8, buf: *mut u8, len: usize) -> SysResult {
    unsafe { sc!(nr::READLINKAT, dirfd, path, buf, len) }
}
pub unsafe fn faccessat(dirfd: i32, path: *const u8, mode: u32) -> SysResult {
    unsafe { sc!(nr::FACCESSAT, dirfd, path, mode) }
}
pub unsafe fn getdents64(fd: i32, buf: *mut u8, len: usize) -> SysResult {
    unsafe { sc!(nr::GETDENTS64, fd, buf, len) }
}
pub unsafe fn getcwd(buf: *mut u8, len: usize) -> SysResult {
    unsafe { sc!(nr::GETCWD, buf, len) }
}
pub unsafe fn chdir(path: *const u8) -> SysResult {
    unsafe { sc!(nr::CHDIR, path) }
}

pub unsafe fn mmap(addr: usize, len: usize, prot: usize, flags: usize, fd: i32, off: usize) -> SysResult {
    unsafe { sc!(nr::MMAP, addr, len, prot, flags, fd as isize, off) }
}
pub unsafe fn munmap(addr: usize, len: usize) -> SysResult {
    unsafe { sc!(nr::MUNMAP, addr, len) }
}
pub unsafe fn mprotect(addr: usize, len: usize, prot: usize) -> SysResult {
    unsafe { sc!(nr::MPROTECT, addr, len, prot) }
}

/// Through the vDSO when there is one ([`crate::vdso`]), else the syscall.
pub fn clock_gettime(clock: usize) -> Timespec {
    let mut ts = Timespec::default();
    if let Some(f) = crate::vdso::clock_gettime()
        && unsafe { f(clock as i32, &mut ts) } == 0
    {
        return ts;
    }
    unsafe { sc!(nr::CLOCK_GETTIME, clock, &mut ts as *mut Timespec) }.expect("clock_gettime failed");
    ts
}
pub const TIMER_ABSTIME: usize = 1;
pub unsafe fn clock_nanosleep(clock: usize, flags: usize, req: *const Timespec, rem: *mut Timespec) -> SysResult {
    unsafe { sc!(nr::CLOCK_NANOSLEEP, clock, flags, req, rem) }
}
pub fn nanosleep(ts: &Timespec) -> SysResult {
    let mut rem = Timespec::default();
    let mut req = *ts;
    loop {
        match unsafe { sc!(nr::CLOCK_NANOSLEEP, CLOCK_MONOTONIC, 0, &req as *const Timespec, &mut rem as *mut Timespec) } {
            Err(EINTR) => req = rem,
            r => return r,
        }
    }
}

pub unsafe fn futex(addr: *const u32, op: usize, val: u32, timeout: *const Timespec) -> SysResult {
    unsafe { sc!(nr::FUTEX, addr, op, val, timeout, 0, 0) }
}
/// `FUTEX_WAIT_BITSET` with every bit set: a private `FUTEX_WAIT` whose
/// timeout is an absolute `CLOCK_MONOTONIC` time.
pub unsafe fn futex_wait_abs(addr: *const u32, val: u32, deadline: *const Timespec) -> SysResult {
    unsafe { sc!(nr::FUTEX, addr, FUTEX_WAIT_BITSET | FUTEX_PRIVATE, val, deadline, 0, !0u32) }
}

pub fn getpid() -> u32 {
    unsafe { sc!(nr::GETPID) }.unwrap_or(0) as u32
}
pub fn gettid() -> u32 {
    unsafe { sc!(nr::GETTID) }.unwrap_or(0) as u32
}
pub fn getuid() -> u32 {
    unsafe { sc!(nr::GETUID) }.unwrap_or(0) as u32
}
pub fn sched_yield() {
    let _ = unsafe { sc!(nr::SCHED_YIELD) };
}
pub unsafe fn sched_getaffinity(buf: *mut u8, len: usize) -> SysResult {
    unsafe { sc!(nr::SCHED_GETAFFINITY, 0, len, buf) }
}
pub fn set_tid_address(addr: *mut u32) -> SysResult {
    unsafe { sc!(nr::SET_TID_ADDRESS, addr) }
}
pub fn kill(pid: i32, sig: usize) -> SysResult {
    unsafe { sc!(nr::KILL, pid as isize, sig) }
}
pub fn tgkill(pid: u32, tid: u32, sig: usize) -> SysResult {
    unsafe { sc!(nr::TGKILL, pid, tid, sig) }
}
pub unsafe fn rt_sigaction(sig: usize, act: *const crate::arch::KSigaction, old: *mut crate::arch::KSigaction) -> SysResult {
    unsafe { sc!(nr::RT_SIGACTION, sig, act, old, 8) }
}
/// `stack_t`, for [`sigaltstack`].
#[repr(C)]
pub struct StackT {
    pub sp: usize,
    pub flags: i32,
    pub size: usize,
}
pub unsafe fn sigaltstack(new: *const StackT, old: *mut StackT) -> SysResult {
    unsafe { sc!(nr::SIGALTSTACK, new, old) }
}
pub unsafe fn rt_sigprocmask(how: usize, set: *const u64, old: *mut u64) -> SysResult {
    unsafe { sc!(nr::RT_SIGPROCMASK, how, set, old, 8) }
}
pub fn exit_group(code: i32) -> ! {
    unsafe {
        let _ = sc!(nr::EXIT_GROUP, code as isize);
        let _ = sc!(nr::EXIT, code as isize);
    }
    unreachable!("exit_group returned")
}
pub fn exit_thread(code: i32) -> ! {
    unsafe {
        let _ = sc!(nr::EXIT, code as isize);
    }
    unreachable!("exit returned")
}
pub unsafe fn getrandom(buf: *mut u8, len: usize, flags: u32) -> SysResult {
    unsafe { sc!(nr::GETRANDOM, buf, len, flags) }
}
/// Sleep until a signal arrives.
pub fn pause() {
    let _ = unsafe { sc!(nr::PPOLL, 0, 0, 0, 0, 8) };
}
pub unsafe fn ppoll(fds: *mut PollFd, n: usize, timeout: *const Timespec) -> SysResult {
    unsafe { sc!(nr::PPOLL, fds, n, timeout, 0, 8) }
}

pub fn setuid(uid: u32) -> SysResult {
    unsafe { sc!(nr::SETUID, uid) }
}
pub fn setgid(gid: u32) -> SysResult {
    unsafe { sc!(nr::SETGID, gid) }
}
pub unsafe fn setgroups(n: usize, groups: *const u32) -> SysResult {
    unsafe { sc!(nr::SETGROUPS, n, groups) }
}
pub fn setpgid(pid: i32, pgid: i32) -> SysResult {
    unsafe { sc!(nr::SETPGID, pid as isize, pgid as isize) }
}
pub fn getpgid(pid: i32) -> SysResult {
    unsafe { sc!(nr::GETPGID, pid as isize) }
}
pub fn setsid() -> SysResult {
    unsafe { sc!(nr::SETSID) }
}
pub fn getppid() -> u32 {
    unsafe { sc!(nr::GETPPID) }.unwrap_or(0) as u32
}
pub fn getgid() -> u32 {
    unsafe { sc!(nr::GETGID) }.unwrap_or(0) as u32
}
pub fn geteuid() -> u32 {
    unsafe { sc!(nr::GETEUID) }.unwrap_or(0) as u32
}
pub fn getegid() -> u32 {
    unsafe { sc!(nr::GETEGID) }.unwrap_or(0) as u32
}
pub unsafe fn readv(fd: i32, iov: *const IoVec, n: usize) -> SysResult {
    unsafe { sc!(nr::READV, fd, iov, n) }
}
pub unsafe fn writev(fd: i32, iov: *const IoVec, n: usize) -> SysResult {
    unsafe { sc!(nr::WRITEV, fd, iov, n) }
}
pub unsafe fn preadv(fd: i32, iov: *const IoVec, n: usize, off: u64) -> SysResult {
    unsafe { sc!(nr::PREADV, fd, iov, n, off, 0) }
}
pub unsafe fn pwritev(fd: i32, iov: *const IoVec, n: usize, off: u64) -> SysResult {
    unsafe { sc!(nr::PWRITEV, fd, iov, n, off, 0) }
}
pub fn fchown(fd: i32, uid: u32, gid: u32) -> SysResult {
    unsafe { sc!(nr::FCHOWN, fd, uid, gid) }
}
pub unsafe fn fchownat(dirfd: i32, path: *const u8, uid: u32, gid: u32, flags: u32) -> SysResult {
    unsafe { sc!(nr::FCHOWNAT, dirfd, path, uid, gid, flags) }
}
pub unsafe fn utimensat(dirfd: i32, path: *const u8, times: *const Timespec, flags: u32) -> SysResult {
    unsafe { sc!(nr::UTIMENSAT, dirfd, path, times, flags) }
}
pub unsafe fn fchmodat2(dirfd: i32, path: *const u8, mode: u32, flags: u32) -> SysResult {
    unsafe { sc!(nr::FCHMODAT2, dirfd, path, mode, flags) }
}
pub unsafe fn chroot(path: *const u8) -> SysResult {
    unsafe { sc!(nr::CHROOT, path) }
}
pub unsafe fn mknodat(dirfd: i32, path: *const u8, mode: u32, dev: u64) -> SysResult {
    unsafe { sc!(nr::MKNODAT, dirfd, path, mode, dev) }
}
pub unsafe fn uname(buf: *mut u8) -> SysResult {
    unsafe { sc!(nr::UNAME, buf) }
}
pub fn fchdir(fd: i32) -> SysResult {
    unsafe { sc!(nr::FCHDIR, fd) }
}
pub fn dup(fd: i32) -> SysResult<i32> {
    unsafe { sc!(nr::DUP, fd).map(|f| f as i32) }
}
pub unsafe fn truncate(path: *const u8, len: u64) -> SysResult {
    unsafe { sc!(nr::TRUNCATE, path, len) }
}
pub fn flock(fd: i32, op: u32) -> SysResult {
    unsafe { sc!(nr::FLOCK, fd, op) }
}
pub unsafe fn ioctl(fd: i32, req: usize, arg: usize) -> SysResult {
    unsafe { sc!(nr::IOCTL, fd, req, arg) }
}
pub unsafe fn prctl(op: usize, a: usize, b: usize, c: usize, d: usize) -> SysResult {
    unsafe { sc!(nr::PRCTL, op, a, b, c, d) }
}
pub unsafe fn socketpair(domain: u16, ty: u32, proto: u32, fds: *mut [i32; 2]) -> SysResult {
    unsafe { sc!(nr::SOCKETPAIR, domain, ty, proto, fds) }
}
pub unsafe fn sendmsg(fd: i32, msg: *const u8, flags: u32) -> SysResult {
    unsafe { sc!(nr::SENDMSG, fd, msg, flags) }
}
pub unsafe fn recvmsg(fd: i32, msg: *mut u8, flags: u32) -> SysResult {
    unsafe { sc!(nr::RECVMSG, fd, msg, flags) }
}
pub unsafe fn copy_file_range(fd_in: i32, off_in: *mut i64, fd_out: i32, off_out: *mut i64, len: usize, flags: u32) -> SysResult {
    unsafe { sc!(nr::COPY_FILE_RANGE, fd_in, off_in, fd_out, off_out, len, flags) }
}
pub unsafe fn sendfile(fd_out: i32, fd_in: i32, off: *mut i64, count: usize) -> SysResult {
    unsafe { sc!(nr::SENDFILE, fd_out, fd_in, off, count) }
}
pub unsafe fn splice(fd_in: i32, off_in: *mut i64, fd_out: i32, off_out: *mut i64, len: usize, flags: u32) -> SysResult {
    unsafe { sc!(nr::SPLICE, fd_in, off_in, fd_out, off_out, len, flags) }
}
pub unsafe fn waitid(idtype: u32, id: u32, info: *mut u8, options: u32) -> SysResult {
    unsafe { sc!(nr::WAITID, idtype, id, info, options, 0) }
}
pub fn pidfd_send_signal(pidfd: i32, sig: i32, flags: u32) -> SysResult {
    unsafe { sc!(nr::PIDFD_SEND_SIGNAL, pidfd, sig, 0, flags) }
}
pub fn pidfd_open(pid: i32, flags: u32) -> SysResult<i32> {
    unsafe { sc!(nr::PIDFD_OPEN, pid, flags).map(|f| f as i32) }
}

/// `fork()` expressed as `clone(SIGCHLD)`; aarch64 has no fork syscall.
pub unsafe fn fork() -> SysResult {
    unsafe { sc!(nr::CLONE, SIGCHLD, 0, 0, 0, 0) }
}
pub unsafe fn execve(path: *const u8, argv: *const *const u8, envp: *const *const u8) -> SysResult {
    unsafe { sc!(nr::EXECVE, path, argv, envp) }
}
pub unsafe fn wait4(pid: i32, status: *mut i32, options: u32) -> SysResult {
    unsafe { sc!(nr::WAIT4, pid as isize, status, options, 0) }
}

pub fn socket(domain: u16, ty: u32, proto: u32) -> SysResult<i32> {
    unsafe { sc!(nr::SOCKET, domain, ty, proto).map(|f| f as i32) }
}
pub unsafe fn bind(fd: i32, addr: *const u8, len: u32) -> SysResult {
    unsafe { sc!(nr::BIND, fd, addr, len) }
}
pub unsafe fn connect(fd: i32, addr: *const u8, len: u32) -> SysResult {
    unsafe { sc!(nr::CONNECT, fd, addr, len) }
}
pub fn listen(fd: i32, backlog: i32) -> SysResult {
    unsafe { sc!(nr::LISTEN, fd, backlog) }
}
pub unsafe fn accept4(fd: i32, addr: *mut u8, len: *mut u32, flags: u32) -> SysResult<i32> {
    unsafe { sc!(nr::ACCEPT4, fd, addr, len, flags).map(|f| f as i32) }
}
pub unsafe fn sendto(fd: i32, buf: *const u8, len: usize, flags: u32, addr: *const u8, alen: u32) -> SysResult {
    unsafe { sc!(nr::SENDTO, fd, buf, len, flags, addr, alen) }
}
pub unsafe fn recvfrom(fd: i32, buf: *mut u8, len: usize, flags: u32, addr: *mut u8, alen: *mut u32) -> SysResult {
    unsafe { sc!(nr::RECVFROM, fd, buf, len, flags, addr, alen) }
}
pub fn shutdown(fd: i32, how: u32) -> SysResult {
    unsafe { sc!(nr::SHUTDOWN, fd, how) }
}
pub unsafe fn getsockname(fd: i32, addr: *mut u8, len: *mut u32) -> SysResult {
    unsafe { sc!(nr::GETSOCKNAME, fd, addr, len) }
}
pub unsafe fn getpeername(fd: i32, addr: *mut u8, len: *mut u32) -> SysResult {
    unsafe { sc!(nr::GETPEERNAME, fd, addr, len) }
}
pub unsafe fn setsockopt(fd: i32, level: u32, name: u32, val: *const u8, len: u32) -> SysResult {
    unsafe { sc!(nr::SETSOCKOPT, fd, level, name, val, len) }
}
pub unsafe fn getsockopt(fd: i32, level: u32, name: u32, val: *mut u8, len: *mut u32) -> SysResult {
    unsafe { sc!(nr::GETSOCKOPT, fd, level, name, val, len) }
}

/// Write all of `buf` to `fd`, ignoring errors. Used by the panic path.
pub fn write_all_raw(fd: i32, mut buf: &[u8]) {
    while !buf.is_empty() {
        match unsafe { write(fd, buf.as_ptr(), buf.len()) } {
            Ok(0) => return,
            Ok(n) => buf = &buf[n..],
            Err(EINTR) => {}
            Err(_) => return,
        }
    }
}

/// Short description of an errno value, as `strerror` would give.
pub const fn strerror(e: i32) -> &'static str {
    match e {
        EPERM => "Operation not permitted",
        ENOENT => "No such file or directory",
        3 => "No such process",
        EINTR => "Interrupted system call",
        EIO => "Input/output error",
        6 => "No such device or address",
        7 => "Argument list too long",
        8 => "Exec format error",
        EBADF => "Bad file descriptor",
        ECHILD => "No child processes",
        EAGAIN => "Resource temporarily unavailable",
        ENOMEM => "Cannot allocate memory",
        EACCES => "Permission denied",
        14 => "Bad address",
        EBUSY => "Device or resource busy",
        EEXIST => "File exists",
        EXDEV => "Invalid cross-device link",
        19 => "No such device",
        ENOTDIR => "Not a directory",
        EISDIR => "Is a directory",
        EINVAL => "Invalid argument",
        23 => "Too many open files in system",
        24 => "Too many open files",
        25 => "Inappropriate ioctl for device",
        ETXTBSY => "Text file busy",
        EFBIG => "File too large",
        ENOSPC => "No space left on device",
        ESPIPE => "Illegal seek",
        EROFS => "Read-only file system",
        EMLINK => "Too many links",
        EPIPE => "Broken pipe",
        33 => "Numerical argument out of domain",
        34 => "Numerical result out of range",
        EDEADLK => "Resource deadlock avoided",
        ENAMETOOLONG => "File name too long",
        ENOSYS => "Function not implemented",
        ENOTEMPTY => "Directory not empty",
        ELOOP => "Too many levels of symbolic links",
        EOVERFLOW => "Value too large for defined data type",
        88 => "Socket operation on non-socket",
        95 => "Operation not supported",
        97 => "Address family not supported by protocol",
        EADDRINUSE => "Address already in use",
        EADDRNOTAVAIL => "Cannot assign requested address",
        ENETDOWN => "Network is down",
        ENETUNREACH => "Network is unreachable",
        ECONNABORTED => "Software caused connection abort",
        ECONNRESET => "Connection reset by peer",
        106 => "Transport endpoint is already connected",
        ENOTCONN => "Transport endpoint is not connected",
        ETIMEDOUT => "Connection timed out",
        ECONNREFUSED => "Connection refused",
        EHOSTUNREACH => "No route to host",
        EINPROGRESS => "Operation now in progress",
        _ => "Unknown error",
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Raw syscall returns decode to `Err(errno)` exactly for -4095..=-1.
    #[kani::proof]
    fn syscall_return_decoding() {
        let ret: usize = kani::any();
        match check(ret) {
            Ok(v) => {
                assert_eq!(v, ret);
                assert!(!(-4095..=-1).contains(&(ret as isize)));
            }
            Err(e) => {
                assert!((1..=4095).contains(&e));
                assert_eq!(ret as isize, -(e as isize));
            }
        }
    }
}
