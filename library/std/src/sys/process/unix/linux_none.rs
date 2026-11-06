//! Spawning and waiting on linux-none: `linux_none_rt::process` starts the
//! child (`clone` + `execve`, searching `PATH` like `execvp`); `ExitStatus`
//! and the rest follow unix.rs.

use libc::{c_int, pid_t};
use linux_none_rt::process::{self as rt, Fd};
use linux_none_rt::sys as rsys;

use super::common::*;
use crate::ffi::CStr;
use crate::io::{self, ErrorKind};
use crate::num::NonZero;
use crate::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use crate::process::StdioPipes;
use crate::sys::fd::FileDesc;
use crate::sys::{AsInner, FromInner, IntoInner, cvt, cvt_r};
use crate::{fmt, sys};

/// `execvp`'s search path when the environment has no `PATH` (musl's).
const DEFAULT_PATH: &[u8] = b"/usr/local/bin:/bin:/usr/bin";

////////////////////////////////////////////////////////////////////////////////
// Command
////////////////////////////////////////////////////////////////////////////////

impl Command {
    pub fn spawn(
        &mut self,
        default: Stdio,
        needs_stdin: bool,
    ) -> io::Result<(Process, StdioPipes)> {
        let envp = self.capture_env();

        if self.saw_nul() {
            return Err(io::const_error!(
                ErrorKind::InvalidInput,
                "nul byte found in provided data",
            ));
        }

        let (ours, theirs) = self.setup_io(default, needs_stdin)?;

        // the child reads PATH, and the parent's environ when it is
        // inherited: keep setenv out until it has exec'd
        let env_lock = sys::env::env_read_lock();
        let pid = self.with_spawn(&theirs, envp.as_ref(), |s| cvt(unsafe { rt::spawn(s) }))?;
        drop(env_lock);

        let pidfd = if self.get_create_pidfd() {
            // the child cannot be reaped (and its pid reused) before we wait for it
            rsys::pidfd_open(pid, 0).ok()
        } else {
            None
        };
        let p = unsafe { Process::new(pid, pidfd.unwrap_or(-1)) };
        Ok((p, ours))
    }

    pub fn exec(&mut self, default: Stdio) -> io::Error {
        let envp = self.capture_env();

        if self.saw_nul() {
            return io::const_error!(ErrorKind::InvalidInput, "nul byte found in provided data");
        }

        match self.setup_io(default, true) {
            Ok((_, theirs)) => {
                let _lock = sys::env::env_read_lock();
                let r: io::Result<!> = self.with_spawn(&theirs, envp.as_ref(), |s| {
                    Err(io::Error::from_raw_os_error(unsafe { rt::exec(s) }))
                });
                let Err(e) = r;
                e
            }
            Err(e) => e,
        }
    }

    /// Describe the child to `linux_none_rt::process` and call `f` with it.
    fn with_spawn<T>(
        &mut self,
        stdio: &ChildPipes,
        envp: Option<&CStringArray>,
        f: impl FnOnce(&mut rt::Spawn<'_>) -> io::Result<T>,
    ) -> io::Result<T> {
        let envp = match envp {
            Some(e) => e.as_ptr().cast(),
            None => sys::env::environ().cast(),
        };
        let fd = |c: &ChildStdio| c.fd().map_or(Fd::Inherit, Fd::Dup);
        let stdio = [fd(&stdio.stdin), fd(&stdio.stdout), fd(&stdio.stderr)];

        // `execvp` searches the child's PATH
        let path: Option<Vec<u8>> = if self.program_is_path() {
            None
        } else {
            Some(child_env_path(envp).unwrap_or_else(|| DEFAULT_PATH.to_vec()))
        };

        let program = self.get_program_cstr().as_ptr().cast();
        let argv = self.get_argv().as_ptr().cast();
        let cwd = self.get_cwd().map(|c| c.as_ptr().cast());
        let chroot = self.get_chroot().map(|c| c.as_ptr().cast());
        let (uid, gid, pgroup, setsid) =
            (self.get_uid(), self.get_gid(), self.get_pgroup(), self.get_setsid());
        let groups: Option<Vec<u32>> = self.get_groups().map(|g| g.to_vec());

        let closures = self.get_closures();
        let has_closures = !closures.is_empty();
        let mut run_closures = || -> Result<(), i32> {
            for callback in closures.iter_mut() {
                callback().map_err(|e| e.raw_os_error().unwrap_or(libc::EINVAL))?;
            }
            Ok(())
        };

        let mut s = rt::Spawn {
            program,
            search_path: path.as_deref(),
            argv,
            envp,
            chroot,
            cwd,
            stdio,
            uid,
            gid,
            groups: groups.as_deref(),
            pgroup,
            setsid,
            reset_sigpipe: !crate::sys::pal::on_broken_pipe_used(),
            pre_exec: if has_closures { Some(&mut run_closures) } else { None },
        };
        f(&mut s)
    }
}

/// The `PATH` in a null-terminated `KEY=VALUE` array.
fn child_env_path(envp: *const *const u8) -> Option<Vec<u8>> {
    let mut p = envp;
    unsafe {
        while !p.is_null() && !(*p).is_null() {
            let entry = CStr::from_ptr((*p).cast()).to_bytes();
            if let Some(v) = entry.strip_prefix(b"PATH=") {
                return Some(v.to_vec());
            }
            p = p.add(1);
        }
    }
    None
}

////////////////////////////////////////////////////////////////////////////////
// Processes
////////////////////////////////////////////////////////////////////////////////

/// The unique ID of the process (this should never be negative).
pub struct Process {
    pid: pid_t,
    status: Option<ExitStatus>,
    // Stores the pidfd created for this child, if the user requested one and
    // `pidfd_open` succeeded.
    pidfd: Option<PidFd>,
}

impl Process {
    /// # Safety
    ///
    /// `pidfd` must either be -1 (representing no file descriptor) or a valid, exclusively owned file
    /// descriptor (See [I/O Safety]).
    ///
    /// [I/O Safety]: crate::io#io-safety
    unsafe fn new(pid: pid_t, pidfd: pid_t) -> Self {
        // Safety: If `pidfd` is nonnegative, we assume it's valid and otherwise unowned.
        let pidfd = (pidfd >= 0).then(|| PidFd::from_inner(unsafe { FileDesc::from_raw_fd(pidfd) }));
        Process { pid, status: None, pidfd }
    }

    pub fn id(&self) -> u32 {
        self.pid as u32
    }

    pub fn kill(&self) -> io::Result<()> {
        self.send_signal(libc::SIGKILL)
    }

    pub(crate) fn send_signal(&self, signal: i32) -> io::Result<()> {
        // If we've already waited on this process then the pid can be recycled and
        // used for another process, and we probably shouldn't be sending signals to
        // random processes, so return Ok because the process has exited already.
        if self.status.is_some() {
            return Ok(());
        }
        if let Some(pid_fd) = self.pidfd.as_ref() {
            return pid_fd.send_signal(signal);
        }
        cvt(rsys::kill(self.pid, signal as usize)).map(drop)
    }

    pub(crate) fn send_process_group_signal(&self, signal: i32) -> io::Result<()> {
        // See note in `send_signal` regarding recycled PIDs.
        if self.status.is_some() {
            return Ok(());
        }
        if let Some(pid_fd) = self.pidfd.as_ref() {
            // The `PIDFD_SIGNAL_PROCESS_GROUP` flag requires kernel >= 6.9
            return pid_fd.send_process_group_signal(signal);
        }
        // killpg
        cvt(rsys::kill(-self.pid, signal as usize)).map(drop)
    }

    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        if let Some(status) = self.status {
            return Ok(status);
        }
        if let Some(pid_fd) = self.pidfd.as_ref() {
            let status = pid_fd.wait()?;
            self.status = Some(status);
            return Ok(status);
        }
        let mut status = 0 as c_int;
        cvt_r(|| unsafe { rsys::wait4(self.pid, &mut status, 0) })?;
        self.status = Some(ExitStatus::new(status));
        Ok(ExitStatus::new(status))
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if let Some(status) = self.status {
            return Ok(Some(status));
        }
        if let Some(pid_fd) = self.pidfd.as_ref() {
            let status = pid_fd.try_wait()?;
            if let Some(status) = status {
                self.status = Some(status)
            }
            return Ok(status);
        }
        let mut status = 0 as c_int;
        let pid = cvt(unsafe { rsys::wait4(self.pid, &mut status, libc::WNOHANG as u32) })?;
        if pid == 0 {
            Ok(None)
        } else {
            self.status = Some(ExitStatus::new(status));
            Ok(Some(ExitStatus::new(status)))
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// PidFd
////////////////////////////////////////////////////////////////////////////////

const PIDFD_SIGNAL_PROCESS_GROUP: u32 = 1 << 2;
const P_PIDFD: u32 = 3;

#[derive(Debug)]
pub struct PidFd(FileDesc);

impl PidFd {
    pub fn kill(&self) -> io::Result<()> {
        self.send_signal(libc::SIGKILL)
    }

    #[cfg(test)]
    pub fn current_process() -> io::Result<PidFd> {
        let pid = crate::process::id();
        let pidfd = cvt(rsys::pidfd_open(pid as i32, 0))?;
        Ok(unsafe { PidFd::from_raw_fd(pidfd as RawFd) })
    }

    #[cfg(test)]
    pub fn pid(&self) -> io::Result<u32> {
        // since kernel 6.13
        let mut pidfd_info: libc::pidfd_info = unsafe { crate::mem::zeroed() };
        pidfd_info.mask = libc::PIDFD_INFO_PID as u64;
        self.get_info(&mut pidfd_info)?;
        Ok(pidfd_info.pid)
    }

    fn get_info(&self, info: &mut libc::pidfd_info) -> io::Result<()> {
        let req = libc::PIDFD_GET_INFO as usize;
        cvt(unsafe { rsys::ioctl(self.0.as_raw_fd(), req, info as *mut _ as usize) }).map(drop)
    }

    fn exit_for_reaped_child(&self) -> io::Result<ExitStatus> {
        // since kernel 6.15
        let mut pidfd_info: libc::pidfd_info = unsafe { crate::mem::zeroed() };
        pidfd_info.mask = libc::PIDFD_INFO_EXIT as u64;
        self.get_info(&mut pidfd_info)?;
        Ok(ExitStatus::new(pidfd_info.exit_code))
    }

    fn waitid(&self, options: c_int) -> io::Result<Option<ExitStatus>> {
        let mut siginfo: libc::siginfo_t = unsafe { crate::mem::zeroed() };
        let r = cvt_r(|| unsafe {
            rsys::waitid(
                P_PIDFD,
                self.0.as_raw_fd() as u32,
                (&raw mut siginfo).cast(),
                options as u32,
            )
        });
        match r {
            Err(waitid_err) if waitid_err.raw_os_error() == Some(libc::ECHILD) => {
                // already reaped
                match self.exit_for_reaped_child() {
                    Ok(exit_status) => return Ok(Some(exit_status)),
                    Err(_) => return Err(waitid_err),
                }
            }
            Err(e) => return Err(e),
            Ok(_) => {}
        }
        if unsafe { siginfo.si_pid() } == 0 {
            Ok(None)
        } else {
            Ok(Some(ExitStatus::from_waitid_siginfo(siginfo)))
        }
    }

    fn pidfd_send_signal(&self, signal: i32, flags: u32) -> io::Result<()> {
        cvt(rsys::pidfd_send_signal(self.0.as_raw_fd(), signal, flags)).map(drop)
    }

    pub fn send_signal(&self, signal: i32) -> io::Result<()> {
        self.pidfd_send_signal(signal, 0)
    }

    pub fn send_process_group_signal(&self, signal: i32) -> io::Result<()> {
        // since kernel 6.9
        self.pidfd_send_signal(signal, PIDFD_SIGNAL_PROCESS_GROUP)
    }

    pub fn wait(&self) -> io::Result<ExitStatus> {
        let r = self.waitid(libc::WEXITED)?;
        match r {
            Some(exit_status) => Ok(exit_status),
            None => unreachable!("waitid with WEXITED should not return None"),
        }
    }

    pub fn try_wait(&self) -> io::Result<Option<ExitStatus>> {
        self.waitid(libc::WEXITED | libc::WNOHANG)
    }
}

impl AsInner<FileDesc> for PidFd {
    fn as_inner(&self) -> &FileDesc {
        &self.0
    }
}

impl IntoInner<FileDesc> for PidFd {
    fn into_inner(self) -> FileDesc {
        self.0
    }
}

impl FromInner<FileDesc> for PidFd {
    fn from_inner(inner: FileDesc) -> Self {
        Self(inner)
    }
}

impl FromRawFd for PidFd {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Self(unsafe { FileDesc::from_raw_fd(fd) })
    }
}

impl IntoRawFd for PidFd {
    fn into_raw_fd(self) -> RawFd {
        self.0.into_raw_fd()
    }
}

////////////////////////////////////////////////////////////////////////////////
// ExitStatus
////////////////////////////////////////////////////////////////////////////////

/// Unix exit statuses
//
// This is not actually an "exit status" in Unix terminology.  Rather, it is a "wait status".
// See the discussion in comments and doc comments for `std::process::ExitStatus`.
#[derive(PartialEq, Eq, Clone, Copy, Default)]
pub struct ExitStatus(c_int);

impl fmt::Debug for ExitStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("unix_wait_status").field(&self.0).finish()
    }
}

impl ExitStatus {
    pub fn new(status: c_int) -> ExitStatus {
        ExitStatus(status)
    }

    pub fn from_waitid_siginfo(siginfo: libc::siginfo_t) -> ExitStatus {
        let status = unsafe { siginfo.si_status() };

        match siginfo.si_code {
            libc::CLD_EXITED => ExitStatus((status & 0xff) << 8),
            libc::CLD_KILLED => ExitStatus(status),
            libc::CLD_DUMPED => ExitStatus(status | 0x80),
            libc::CLD_CONTINUED => ExitStatus(0xffff),
            libc::CLD_STOPPED | libc::CLD_TRAPPED => ExitStatus(((status & 0xff) << 8) | 0x7f),
            _ => unreachable!("waitid() should only return the above codes"),
        }
    }

    fn exited(&self) -> bool {
        libc::WIFEXITED(self.0)
    }

    pub fn exit_ok(&self) -> Result<(), ExitStatusError> {
        // This assumes that WIFEXITED(status) && WEXITSTATUS==0 corresponds to status==0, as
        // unix.rs does.
        match NonZero::try_from(self.0) {
            /* was nonzero */ Ok(failure) => Err(ExitStatusError(failure)),
            /* was zero, couldn't convert */ Err(_) => Ok(()),
        }
    }

    pub fn code(&self) -> Option<i32> {
        self.exited().then(|| libc::WEXITSTATUS(self.0))
    }

    pub fn signal(&self) -> Option<i32> {
        libc::WIFSIGNALED(self.0).then(|| libc::WTERMSIG(self.0))
    }

    pub fn core_dumped(&self) -> bool {
        libc::WIFSIGNALED(self.0) && libc::WCOREDUMP(self.0)
    }

    pub fn stopped_signal(&self) -> Option<i32> {
        libc::WIFSTOPPED(self.0).then(|| libc::WSTOPSIG(self.0))
    }

    pub fn continued(&self) -> bool {
        libc::WIFCONTINUED(self.0)
    }

    pub fn into_raw(&self) -> c_int {
        self.0
    }
}

/// Converts a raw `c_int` to a type-safe `ExitStatus` by wrapping it without copying.
impl From<c_int> for ExitStatus {
    fn from(a: c_int) -> ExitStatus {
        ExitStatus(a)
    }
}

impl fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(code) = self.code() {
            write!(f, "exit status: {code}")
        } else if let Some(signal) = self.signal() {
            if self.core_dumped() {
                write!(f, "signal: {signal} (core dumped)")
            } else {
                write!(f, "signal: {signal}")
            }
        } else if let Some(signal) = self.stopped_signal() {
            write!(f, "stopped (not terminated) by signal: {signal}")
        } else if self.continued() {
            write!(f, "continued (WIFCONTINUED)")
        } else {
            write!(f, "unrecognised wait status: {} {:#x}", self.0, self.0)
        }
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct ExitStatusError(NonZero<c_int>);

impl Into<ExitStatus> for ExitStatusError {
    fn into(self) -> ExitStatus {
        ExitStatus(self.0.into())
    }
}

impl fmt::Debug for ExitStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("unix_wait_status").field(&self.0).finish()
    }
}

impl ExitStatusError {
    pub fn code(self) -> Option<NonZero<i32>> {
        ExitStatus(self.0.into()).code().map(|st| st.try_into().unwrap())
    }
}

mod linux_child_ext {
    use crate::io::ErrorKind;
    use crate::os::linux::process as os;
    use crate::sys::{FromInner, process as imp};
    use crate::{io, mem};

    #[unstable(feature = "linux_pidfd", issue = "82971")]
    impl crate::os::linux::process::ChildExt for crate::process::Child {
        fn pidfd(&self) -> io::Result<&os::PidFd> {
            self.handle
                .pidfd
                .as_ref()
                // SAFETY: The os type is a transparent wrapper, therefore we can transmute references
                .map(|fd| unsafe { mem::transmute::<&imp::PidFd, &os::PidFd>(fd) })
                .ok_or_else(|| io::const_error!(ErrorKind::Uncategorized, "no pidfd was created."))
        }

        fn into_pidfd(mut self) -> Result<os::PidFd, Self> {
            self.handle
                .pidfd
                .take()
                .map(<os::PidFd as FromInner<imp::PidFd>>::from_inner)
                .ok_or_else(|| self)
        }
    }
}

#[cfg(test)]
#[path = "unix/tests.rs"]
mod tests;
