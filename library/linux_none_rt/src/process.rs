//! Starting child processes: `clone` + `execve`, as `posix_spawn` and
//! `fork` + `exec` do in libc.
//!
//! Without pre-exec callbacks the child shares the parent's memory and runs
//! on a small stack of its own (`CLONE_VM | CLONE_VFORK`); the parent sleeps
//! until it has called `execve` or failed. With callbacks (which may run
//! arbitrary code) it is a full copy (`fork`). Either way a close-on-exec
//! pipe carries the errno of a failure back to the parent.

use crate::sys::{self, SysResult};

/// What to do with a standard stream of the child.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fd {
    /// keep the parent's
    Inherit,
    /// make this descriptor of the parent the child's
    Dup(i32),
}

/// A program to start. All pointers are to NUL-terminated strings, or
/// null-terminated arrays of them, that live until [`spawn`] returns.
pub struct Spawn<'a> {
    /// the program: a path, or (with `search_path`) a name to look up
    pub program: *const u8,
    /// with a program name without `/`: the `PATH` value to search
    pub search_path: Option<&'a [u8]>,
    pub argv: *const *const u8,
    pub envp: *const *const u8,
    pub chroot: Option<*const u8>,
    pub cwd: Option<*const u8>,
    pub stdio: [Fd; 3],
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub groups: Option<&'a [u32]>,
    pub pgroup: Option<i32>,
    pub setsid: bool,
    /// restore SIGPIPE to its default disposition in the child
    pub reset_sigpipe: bool,
    /// run in the child before `execve`; an `Err(errno)` aborts the spawn
    pub pre_exec: Option<&'a mut dyn FnMut() -> Result<(), i32>>,
}

const CHILD_STACK: usize = 64 * 1024;

/// Start the child. Returns its pid, or the errno with which setting it up or
/// `execve` failed (the failed child is reaped).
///
/// # Safety
/// The pointers in `s` must be valid as documented on [`Spawn`].
pub unsafe fn spawn(s: &mut Spawn<'_>) -> SysResult<i32> {
    // Block all signals while the child runs on our memory: a handler must
    // not run on its stack, and it unblocks them once it has reset the
    // dispositions (handlers do not survive execve, but the mask does).
    let all: u64 = !0;
    let mut old: u64 = 0;
    unsafe { sys::rt_sigprocmask(sys::SIG_SETMASK, &all, &mut old)? };
    let r = if s.pre_exec.is_some() { unsafe { spawn_fork(s, old) } } else { unsafe { spawn_vfork(s, old) } };
    unsafe { sys::rt_sigprocmask(sys::SIG_SETMASK, &old, core::ptr::null_mut())? };
    r
}

struct VforkArg<'s, 'a> {
    s: &'s mut Spawn<'a>,
    mask: u64,
    /// write end of the error pipe
    err: i32,
}

unsafe fn spawn_vfork(s: &mut Spawn<'_>, mask: u64) -> SysResult<i32> {
    let [r, w] = sys::pipe2(sys::O_CLOEXEC)?;
    let stack = match unsafe {
        sys::mmap(0, CHILD_STACK, sys::PROT_READ | sys::PROT_WRITE, sys::MAP_PRIVATE | sys::MAP_ANONYMOUS, -1, 0)
    } {
        Ok(stack) => stack,
        Err(e) => {
            let _ = (sys::close(r), sys::close(w));
            return Err(e);
        }
    };
    let arg = VforkArg { s, mask, err: w };
    // the trampoline pops `vfork_child` then `&arg` off the new stack
    let sp = (stack + CHILD_STACK - 16) as *mut usize;
    unsafe {
        *sp = vfork_child as extern "C" fn(*mut u8) -> ! as usize;
        *sp.add(1) = &arg as *const VforkArg<'_, '_> as usize;
    }
    let flags = sys::CLONE_VM | sys::CLONE_VFORK | sys::SIGCHLD;
    let pid = unsafe { crate::arch::clone_thread(flags, sp, core::ptr::null_mut(), core::ptr::null_mut(), 0) };
    let _ = unsafe { sys::munmap(stack, CHILD_STACK) };
    let _ = sys::close(w);
    if pid < 0 {
        let _ = sys::close(r);
        return Err(-pid as i32);
    }
    wait_exec(r, pid as i32)
}

extern "C" fn vfork_child(arg: *mut u8) -> ! {
    let arg = unsafe { &mut *(arg as *mut VforkArg<'_, '_>) };
    let e = unsafe { child(arg.s, arg.mask) };
    report(arg.err, e)
}

unsafe fn spawn_fork(s: &mut Spawn<'_>, mask: u64) -> SysResult<i32> {
    let [r, w] = sys::pipe2(sys::O_CLOEXEC)?;
    let pid = match unsafe { sys::fork() } {
        Ok(p) => p as i32,
        Err(e) => {
            let _ = sys::close(r);
            let _ = sys::close(w);
            return Err(e);
        }
    };
    if pid == 0 {
        let _ = sys::close(r);
        let e = unsafe { child(s, mask) };
        report(w, e)
    }
    let _ = sys::close(w);
    wait_exec(r, pid)
}

/// In the child: send the errno that stopped it to the parent, and exit.
fn report(pipe: i32, errno: i32) -> ! {
    let b = errno.to_ne_bytes();
    let _ = unsafe { sys::write(pipe, b.as_ptr(), 4) };
    sys::exit_group(127)
}

/// In the parent: wait for the child to exec (the close-on-exec pipe reads
/// EOF) or to report an errno. Even with `CLONE_VFORK` the errno comes
/// through the pipe rather than shared memory: qemu-user, for one, runs
/// such a child as a plain fork.
fn wait_exec(r: i32, pid: i32) -> SysResult<i32> {
    let mut b = [0u8; 4];
    let n = loop {
        match unsafe { sys::read(r, b.as_mut_ptr(), 4) } {
            Err(sys::EINTR) => {}
            r => break r,
        }
    };
    let _ = sys::close(r);
    match n {
        // EOF: the pipe closed on a successful execve
        Ok(0) => Ok(pid),
        Ok(4) => {
            reap(pid);
            Err(i32::from_ne_bytes(b))
        }
        _ => {
            reap(pid);
            Err(sys::EIO)
        }
    }
}

/// Set up the calling process as [`spawn`] would set up a child, then
/// `execve` in place (`CommandExt::exec`). Returns the errno of whatever
/// failed; the process may be partly set up by then.
///
/// # Safety
/// As for [`spawn`].
pub unsafe fn exec(s: &mut Spawn<'_>) -> i32 {
    let mut mask: u64 = 0;
    if let Err(e) = unsafe { sys::rt_sigprocmask(sys::SIG_SETMASK, core::ptr::null(), &mut mask) } {
        return e;
    }
    unsafe { child(s, mask) }
}

fn reap(pid: i32) {
    let mut status = 0;
    while let Err(sys::EINTR) = unsafe { sys::wait4(pid, &mut status, 0) } {}
}

/// Set up the child and exec. Returns the errno of whatever failed.
unsafe fn child(s: &mut Spawn<'_>, mask: u64) -> i32 {
    match unsafe { child_setup(s, mask) } {
        Ok(()) => {}
        Err(e) => return e,
    }
    unsafe { execvp(s) }
}

unsafe fn child_setup(s: &mut Spawn<'_>, mask: u64) -> SysResult<()> {
    for (target, fd) in s.stdio.iter().enumerate() {
        if let Fd::Dup(fd) = *fd {
            let target = target as i32;
            if fd == target {
                // already in place: just let it survive execve
                sys::fcntl(fd, sys::F_SETFD, 0)?;
            } else {
                sys::dup3(fd, target, 0)?;
            }
        }
    }
    if let Some(groups) = s.groups {
        unsafe { sys::setgroups(groups.len(), groups.as_ptr())? };
    }
    if let Some(gid) = s.gid {
        sys::setgid(gid)?;
    }
    if let Some(uid) = s.uid {
        // dropping root privileges also drops supplementary groups, unless
        // they were set explicitly
        if s.groups.is_none() && sys::getuid() == 0 {
            let _ = unsafe { sys::setgroups(0, core::ptr::null()) };
        }
        sys::setuid(uid)?;
    }
    if let Some(dir) = s.chroot {
        unsafe { sys::chroot(dir)? };
    }
    if let Some(cwd) = s.cwd {
        unsafe { sys::chdir(cwd)? };
    }
    if let Some(pg) = s.pgroup {
        sys::setpgid(0, pg)?;
    }
    if s.setsid {
        sys::setsid()?;
    }
    if s.reset_sigpipe {
        let act = crate::arch::KSigaction { handler: sys::SIG_DFL, flags: 0, restorer: 0, mask: 0 };
        unsafe { sys::rt_sigaction(sys::SIGPIPE, &act, core::ptr::null_mut())? };
    }
    if let Some(f) = s.pre_exec.as_mut() {
        f()?;
    }
    // the parent's mask from before spawn, which blocked everything
    unsafe { sys::rt_sigprocmask(sys::SIG_SETMASK, &mask, core::ptr::null_mut())? };
    Ok(())
}

/// `execve`, or `execvp`'s search of `PATH`.
unsafe fn execvp(s: &Spawn<'_>) -> i32 {
    let Some(path) = s.search_path else {
        return unsafe { sys::execve(s.program, s.argv, s.envp) }.unwrap_err();
    };
    let name = unsafe { cstr_bytes(s.program) };
    let mut buf = [0u8; 4096];
    let mut err = sys::ENOENT;
    for dir in path.split(|&b| b == b':') {
        // an empty entry is the current directory
        let dir: &[u8] = if dir.is_empty() { b"." } else { dir };
        let len = dir.len() + 1 + name.len();
        if len >= buf.len() {
            err = sys::ENAMETOOLONG;
            continue;
        }
        buf[..dir.len()].copy_from_slice(dir);
        buf[dir.len()] = b'/';
        buf[dir.len() + 1..len].copy_from_slice(name);
        buf[len] = 0;
        match unsafe { sys::execve(buf.as_ptr(), s.argv, s.envp) }.unwrap_err() {
            // like execvp: keep looking, but report EACCES if nothing else turns up
            sys::EACCES => err = sys::EACCES,
            sys::ENOENT | sys::ENOTDIR | sys::ENAMETOOLONG | sys::ELOOP | sys::ENODEV | sys::ETIMEDOUT
            | sys::ESTALE => {}
            e => return e,
        }
    }
    err
}

unsafe fn cstr_bytes<'a>(p: *const u8) -> &'a [u8] {
    let mut n = 0;
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    unsafe { core::slice::from_raw_parts(p, n) }
}
