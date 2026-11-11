//! x86_64 Linux: syscall ABI, process entry, thread creation, thread pointer.

use core::arch::{asm, naked_asm};

pub mod nr {
    pub const SET_TID_ADDRESS: usize = 218;
    pub const READ: usize = 0;
    pub const WRITE: usize = 1;
    pub const CLOSE: usize = 3;
    pub const LSEEK: usize = 8;
    pub const MMAP: usize = 9;
    pub const MPROTECT: usize = 10;
    pub const MUNMAP: usize = 11;
    pub const RT_SIGACTION: usize = 13;
    pub const RT_SIGPROCMASK: usize = 14;
    pub const IOCTL: usize = 16;
    pub const PREAD64: usize = 17;
    pub const PWRITE64: usize = 18;
    pub const SCHED_YIELD: usize = 24;
    pub const GETPID: usize = 39;
    pub const SOCKET: usize = 41;
    pub const CONNECT: usize = 42;
    pub const SENDTO: usize = 44;
    pub const RECVFROM: usize = 45;
    pub const SHUTDOWN: usize = 48;
    pub const BIND: usize = 49;
    pub const LISTEN: usize = 50;
    pub const GETSOCKNAME: usize = 51;
    pub const GETPEERNAME: usize = 52;
    pub const SETSOCKOPT: usize = 54;
    pub const GETSOCKOPT: usize = 55;
    pub const CLONE: usize = 56;
    pub const EXECVE: usize = 59;
    pub const EXIT: usize = 60;
    pub const WAIT4: usize = 61;
    pub const KILL: usize = 62;
    pub const FCNTL: usize = 72;
    pub const FSYNC: usize = 74;
    pub const FDATASYNC: usize = 75;
    pub const FTRUNCATE: usize = 77;
    pub const GETCWD: usize = 79;
    pub const CHDIR: usize = 80;
    pub const FCHMOD: usize = 91;
    pub const GETUID: usize = 102;
    pub const ARCH_PRCTL: usize = 158;
    pub const GETTID: usize = 186;
    pub const FUTEX: usize = 202;
    pub const SCHED_GETAFFINITY: usize = 204;
    pub const GETDENTS64: usize = 217;
    pub const CLOCK_GETTIME: usize = 228;
    pub const CLOCK_NANOSLEEP: usize = 230;
    pub const EXIT_GROUP: usize = 231;
    pub const TGKILL: usize = 234;
    pub const OPENAT: usize = 257;
    pub const MKDIRAT: usize = 258;
    pub const UNLINKAT: usize = 263;
    pub const LINKAT: usize = 265;
    pub const SYMLINKAT: usize = 266;
    pub const READLINKAT: usize = 267;
    pub const FCHMODAT: usize = 268;
    pub const FACCESSAT: usize = 269;
    pub const PPOLL: usize = 271;
    pub const ACCEPT4: usize = 288;
    pub const DUP3: usize = 292;
    pub const PIPE2: usize = 293;
    pub const RENAMEAT2: usize = 316;
    pub const GETRANDOM: usize = 318;
    pub const STATX: usize = 332;
    pub const READV: usize = 19;
    pub const WRITEV: usize = 20;
    pub const PREADV: usize = 295;
    pub const PWRITEV: usize = 296;
    pub const SETUID: usize = 105;
    pub const SETGID: usize = 106;
    pub const SETGROUPS: usize = 116;
    pub const SETPGID: usize = 109;
    pub const SETSID: usize = 112;
    pub const GETPGID: usize = 121;
    pub const GETPPID: usize = 110;
    pub const GETGID: usize = 104;
    pub const GETEUID: usize = 107;
    pub const GETEGID: usize = 108;
    pub const FCHOWN: usize = 93;
    pub const FCHOWNAT: usize = 260;
    pub const UTIMENSAT: usize = 280;
    pub const FCHDIR: usize = 81;
    pub const SOCKETPAIR: usize = 53;
    pub const SENDMSG: usize = 46;
    pub const RECVMSG: usize = 47;
    pub const FLOCK: usize = 73;
    pub const COPY_FILE_RANGE: usize = 326;
    pub const SENDFILE: usize = 40;
    pub const SPLICE: usize = 275;
    pub const UNAME: usize = 63;
    pub const PRCTL: usize = 157;
    pub const PRLIMIT64: usize = 302;
    pub const SIGALTSTACK: usize = 131;
    pub const MADVISE: usize = 28;
    pub const PIDFD_OPEN: usize = 434;
    pub const PIDFD_SEND_SIGNAL: usize = 424;
    pub const WAITID: usize = 247;
    pub const FSTATFS: usize = 138;
    pub const MREMAP: usize = 25;
    pub const TRUNCATE: usize = 76;
    pub const FCHMODAT2: usize = 452;
    pub const CHROOT: usize = 161;
    pub const MKNODAT: usize = 259;
    pub const RT_SIGRETURN: usize = 15;
    pub const DUP: usize = 32;
    pub const EPOLL_CREATE1: usize = 291;
    pub const EPOLL_CTL: usize = 233;
    pub const EPOLL_PWAIT: usize = 281;
    pub const SYSINFO: usize = 99;
    pub const FACCESSAT2: usize = 439;
    pub const EVENTFD2: usize = 290;
    pub const INOTIFY_INIT1: usize = 294;
    pub const INOTIFY_ADD_WATCH: usize = 254;
    pub const INOTIFY_RM_WATCH: usize = 255;
    pub const STATFS: usize = 137;
    pub const RT_SIGTIMEDWAIT: usize = 128;
    pub const NEWFSTATAT: usize = 262;
    pub const UMASK: usize = 95;
    pub const GETRUSAGE: usize = 98;
    pub const GETSID: usize = 124;
    pub const PSELECT6: usize = 270;
    pub const GETXATTR: usize = 191;
    pub const LGETXATTR: usize = 192;
    pub const LISTXATTR: usize = 194;
    pub const LLISTXATTR: usize = 195;
    pub const SCHED_SETAFFINITY: usize = 203;
    pub const RECVMMSG: usize = 299;
    pub const SENDMMSG: usize = 307;
}

/// # Safety
/// Raw syscall: the arguments must be valid for syscall `n`.
#[inline(always)]
pub unsafe fn syscall6(n: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> usize {
    let ret;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") n => ret,
            in("rdi") a1, in("rsi") a2, in("rdx") a3,
            in("r10") a4, in("r8") a5, in("r9") a6,
            lateout("rcx") _, lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

/// Process entry point. The kernel leaves `argc, argv[], 0, envp[], 0, auxv`
/// at `rsp`; hand that pointer to the runtime.
///
/// # Safety
/// Only the kernel may call this, as the ELF entry point.
#[cfg(linux_none)]
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    naked_asm!(
        "xor ebp, ebp",
        "mov rdi, rsp",
        "and rsp, -16",
        "call {start}",
        "ud2",
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
    naked_asm!(
        "mov r10, rcx",
        "mov eax, {nr}",
        "syscall",
        "test rax, rax",
        "jnz 2f",
        "xor ebp, ebp",
        "pop rax",
        "pop rdi",
        "and rsp, -16",
        "call rax",
        "ud2",
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
            "syscall",
            "xor edi, edi",
            "mov eax, {exit}",
            "syscall",
            "ud2",
            exit = const nr::EXIT,
            in("rax") nr::MUNMAP,
            in("rdi") base,
            in("rsi") len,
            options(noreturn, nostack),
        )
    }
}

/// Make `tp` the thread pointer of the calling thread. The first word at `tp`
/// must be `tp` itself (read back by [`thread_pointer`]).
pub unsafe fn set_thread_pointer(tp: usize) {
    const ARCH_SET_FS: usize = 0x1002;
    unsafe { syscall6(nr::ARCH_PRCTL, ARCH_SET_FS, tp, 0, 0, 0, 0) };
}

#[inline(always)]
pub fn thread_pointer() -> usize {
    let tp;
    unsafe { asm!("mov {}, qword ptr fs:[0]", out(reg) tp, options(nostack, readonly, preserves_flags)) };
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
        "mov eax, {nr}",
        "syscall",
        "ud2",
        nr = const nr::RT_SIGRETURN,
    )
}
