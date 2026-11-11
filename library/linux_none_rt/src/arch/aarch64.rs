//! aarch64 Linux: syscall ABI, process entry, thread creation, thread pointer.

use core::arch::{asm, naked_asm};

/// asm-generic syscall numbers.
pub mod nr {
    pub const SET_TID_ADDRESS: usize = 96;
    pub const GETCWD: usize = 17;
    pub const DUP3: usize = 24;
    pub const FCNTL: usize = 25;
    pub const IOCTL: usize = 29;
    pub const MKDIRAT: usize = 34;
    pub const UNLINKAT: usize = 35;
    pub const SYMLINKAT: usize = 36;
    pub const LINKAT: usize = 37;
    pub const FTRUNCATE: usize = 46;
    pub const FACCESSAT: usize = 48;
    pub const CHDIR: usize = 49;
    pub const FCHMOD: usize = 52;
    pub const FCHMODAT: usize = 53;
    pub const OPENAT: usize = 56;
    pub const CLOSE: usize = 57;
    pub const PIPE2: usize = 59;
    pub const GETDENTS64: usize = 61;
    pub const LSEEK: usize = 62;
    pub const READ: usize = 63;
    pub const WRITE: usize = 64;
    pub const PREAD64: usize = 67;
    pub const PWRITE64: usize = 68;
    pub const PPOLL: usize = 73;
    pub const READLINKAT: usize = 78;
    pub const FSYNC: usize = 82;
    pub const FDATASYNC: usize = 83;
    pub const EXIT: usize = 93;
    pub const EXIT_GROUP: usize = 94;
    pub const FUTEX: usize = 98;
    pub const CLOCK_GETTIME: usize = 113;
    pub const CLOCK_NANOSLEEP: usize = 115;
    pub const SCHED_GETAFFINITY: usize = 123;
    pub const SCHED_YIELD: usize = 124;
    pub const KILL: usize = 129;
    pub const TGKILL: usize = 131;
    pub const RT_SIGACTION: usize = 134;
    pub const RT_SIGPROCMASK: usize = 135;
    pub const GETPID: usize = 172;
    pub const GETUID: usize = 174;
    pub const GETTID: usize = 178;
    pub const SOCKET: usize = 198;
    pub const BIND: usize = 200;
    pub const LISTEN: usize = 201;
    pub const CONNECT: usize = 203;
    pub const GETSOCKNAME: usize = 204;
    pub const GETPEERNAME: usize = 205;
    pub const SENDTO: usize = 206;
    pub const RECVFROM: usize = 207;
    pub const SETSOCKOPT: usize = 208;
    pub const GETSOCKOPT: usize = 209;
    pub const SHUTDOWN: usize = 210;
    pub const MUNMAP: usize = 215;
    pub const CLONE: usize = 220;
    pub const EXECVE: usize = 221;
    pub const MMAP: usize = 222;
    pub const MPROTECT: usize = 226;
    pub const ACCEPT4: usize = 242;
    pub const WAIT4: usize = 260;
    pub const RENAMEAT2: usize = 276;
    pub const GETRANDOM: usize = 278;
    pub const STATX: usize = 291;
    pub const READV: usize = 65;
    pub const WRITEV: usize = 66;
    pub const PREADV: usize = 69;
    pub const PWRITEV: usize = 70;
    pub const SETUID: usize = 146;
    pub const SETGID: usize = 144;
    pub const SETGROUPS: usize = 159;
    pub const SETPGID: usize = 154;
    pub const SETSID: usize = 157;
    pub const GETPGID: usize = 155;
    pub const GETPPID: usize = 173;
    pub const GETGID: usize = 176;
    pub const GETEUID: usize = 175;
    pub const GETEGID: usize = 177;
    pub const FCHOWN: usize = 55;
    pub const FCHOWNAT: usize = 54;
    pub const UTIMENSAT: usize = 88;
    pub const FCHDIR: usize = 50;
    pub const SOCKETPAIR: usize = 199;
    pub const SENDMSG: usize = 211;
    pub const RECVMSG: usize = 212;
    pub const FLOCK: usize = 32;
    pub const COPY_FILE_RANGE: usize = 285;
    pub const SENDFILE: usize = 71;
    pub const SPLICE: usize = 76;
    pub const UNAME: usize = 160;
    pub const PRCTL: usize = 167;
    pub const PRLIMIT64: usize = 261;
    pub const SIGALTSTACK: usize = 132;
    pub const MADVISE: usize = 233;
    pub const PIDFD_OPEN: usize = 434;
    pub const PIDFD_SEND_SIGNAL: usize = 424;
    pub const WAITID: usize = 95;
    pub const FSTATFS: usize = 44;
    pub const MREMAP: usize = 216;
    pub const TRUNCATE: usize = 45;
    pub const FCHMODAT2: usize = 452;
    pub const CHROOT: usize = 51;
    pub const MKNODAT: usize = 33;
    pub const RT_SIGRETURN: usize = 139;
    pub const DUP: usize = 23;
    pub const EPOLL_CREATE1: usize = 20;
    pub const EPOLL_CTL: usize = 21;
    pub const EPOLL_PWAIT: usize = 22;
    pub const SYSINFO: usize = 179;
    pub const FACCESSAT2: usize = 439;
    pub const EVENTFD2: usize = 19;
    pub const INOTIFY_INIT1: usize = 26;
    pub const INOTIFY_ADD_WATCH: usize = 27;
    pub const INOTIFY_RM_WATCH: usize = 28;
    pub const STATFS: usize = 43;
    pub const RT_SIGTIMEDWAIT: usize = 137;
    pub const NEWFSTATAT: usize = 79;
    pub const UMASK: usize = 166;
    pub const GETRUSAGE: usize = 165;
    pub const GETSID: usize = 156;
    pub const PSELECT6: usize = 72;
    pub const GETXATTR: usize = 8;
    pub const LGETXATTR: usize = 9;
    pub const LISTXATTR: usize = 11;
    pub const LLISTXATTR: usize = 12;
    pub const SCHED_SETAFFINITY: usize = 122;
    pub const RECVMMSG: usize = 243;
    pub const SENDMMSG: usize = 269;
}

/// # Safety
/// Raw syscall: the arguments must be valid for syscall `n`.
#[inline(always)]
pub unsafe fn syscall6(n: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> usize {
    let ret;
    unsafe {
        asm!(
            "svc 0",
            in("x8") n,
            inlateout("x0") a1 => ret,
            in("x1") a2, in("x2") a3, in("x3") a4, in("x4") a5, in("x5") a6,
            options(nostack),
        );
    }
    ret
}

/// Process entry point. The kernel leaves `argc, argv[], 0, envp[], 0, auxv`
/// at `sp`; hand that pointer to the runtime.
///
/// # Safety
/// Only the kernel may call this, as the ELF entry point.
#[cfg(linux_none)]
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    naked_asm!(
        "mov x29, xzr",
        "mov x30, xzr",
        "mov x0, sp",
        "and x1, x0, #-16",
        "mov sp, x1",
        "bl {start}",
        "brk #1",
        start = sym crate::start::start,
    )
}

/// `clone(flags, stack, ptid, ctid, tls)`.
///
/// # Safety
/// `stack` must point to the top of a valid stack holding `entry, arg`. In the child, pops `entry` and `arg`
/// from the new stack and calls `entry(arg)`, which must not return.
/// Returns the child tid (or `-errno`) in the parent.
#[unsafe(naked)]
pub unsafe extern "C" fn clone_thread(flags: usize, stack: *mut usize, ptid: *mut u32, ctid: *mut u32, tls: usize) -> isize {
    // the kernel's argument order here is (flags, stack, ptid, tls, ctid)
    naked_asm!(
        "mov x5, x3",
        "mov x3, x4",
        "mov x4, x5",
        "mov x8, #{nr}",
        "svc 0",
        "cbnz x0, 2f",
        "ldp x1, x0, [sp], #16",
        "mov x29, xzr",
        "mov x30, xzr",
        "blr x1",
        "brk #1",
        "2:",
        "ret",
        nr = const nr::CLONE,
    )
}

/// Unmap the calling thread's own stack and exit the thread, touching no
/// memory after the munmap.
pub unsafe fn unmap_stack_and_exit(base: usize, len: usize) -> ! {
    unsafe {
        asm!(
            "svc 0",
            "mov x0, xzr",
            "mov x8, #{exit}",
            "svc 0",
            "brk #1",
            exit = const nr::EXIT,
            in("x8") nr::MUNMAP,
            in("x0") base,
            in("x1") len,
            options(noreturn, nostack),
        )
    }
}

/// Make `tp` the thread pointer of the calling thread.
pub unsafe fn set_thread_pointer(tp: usize) {
    unsafe { asm!("msr tpidr_el0, {}", in(reg) tp, options(nostack, preserves_flags)) };
}

#[inline(always)]
pub fn thread_pointer() -> usize {
    let tp;
    unsafe { asm!("mrs {}, tpidr_el0", out(reg) tp, options(nostack, nomem, preserves_flags)) };
    tp
}

/// `struct sigaction` as the kernel expects it (no libc translation layer).
#[repr(C)]
pub struct KSigaction {
    pub handler: usize,
    pub flags: usize,
    pub restorer: usize,
    pub mask: u64,
}

/// The `sa_restorer` of a signal handler: return from it through
/// `rt_sigreturn`, as libc's `__restore_rt` does.
///
/// # Safety
/// Only the kernel may call this, as a handler's return address.
#[unsafe(naked)]
pub unsafe extern "C" fn restore_rt() -> ! {
    naked_asm!(
        "mov x8, #{nr}",
        "svc 0",
        "brk #1",
        nr = const nr::RT_SIGRETURN,
    )
}
