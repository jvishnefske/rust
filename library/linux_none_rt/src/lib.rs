//! The runtime under std on `*-unknown-linux-none`: everything a libc would
//! provide to std, written against raw Linux syscalls.
//!
//! - [`arch`]: the syscall instruction, the ELF entry point, the `clone`
//!   trampoline and the thread pointer, per architecture.
//! - [`sys`]: typed syscall wrappers returning `Err(errno)`.
//! - [`start`]: process entry (`_start` → C `main`), args/env/auxv, exit.
//! - [`elf`]: the executable's program headers (for TLS and the unwinder).
//! - [`tls`]: ELF thread-local storage from the `PT_TLS` image.
//! - [`thread`]: threads on `clone`, joined through `CLONE_CHILD_CLEARTID`.
//! - [`process`]: child processes on `clone` + `execve`.
//! - [`signal`]: signal handlers on alternate stacks, for std's stack
//!   overflow message.
//! - [`alloc`]: an mmap-backed size-class allocator.
//! - [`futex`], [`locks`]: futex wait/wake and the locks built on them.
//! - [`dirent`]: parsing `getdents64` buffers.
//! - [`dns`]: a DNS stub resolver for `getaddrinfo`.
//! - [`errno`]: the thread's `errno`.
//! - [`vdso`]: finding `clock_gettime` in the kernel's vDSO.
//! - [`passwd`]: home directories from `/etc/passwd`.
//! - [`clib`]: the C library functions crates call through the `libc`
//!   crate (`isatty`, `mmap`, `sysconf`, `sigaction`, `getpwuid_r`, ...).
//!
//! The crate uses only `core`, so std can depend on it. On other Linux
//! targets (where libc is the C runtime) it builds without `_start`.

#![no_std]
#![cfg_attr(linux_none, feature(thread_local, c_variadic))]
#![allow(clippy::missing_safety_doc, clippy::new_without_default)]

#[cfg(target_arch = "aarch64")]
#[path = "arch/aarch64.rs"]
pub mod arch;
#[cfg(target_arch = "x86_64")]
#[path = "arch/x86_64.rs"]
pub mod arch;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("linux_none_rt supports x86_64 and aarch64 only");

#[cfg(not(target_os = "linux"))]
compile_error!("linux_none_rt targets Linux only");

pub mod alloc;
#[cfg(linux_none)]
pub mod clib;
pub mod dirent;
pub mod dns;
pub mod elf;
#[cfg(linux_none)]
pub mod errno;
pub mod futex;
pub mod locks;
pub mod passwd;
pub mod process;
pub mod signal;
pub mod start;
pub mod sys;
pub mod thread;
pub mod tls;
pub mod tz;
pub mod vdso;

pub use arch::nr;
