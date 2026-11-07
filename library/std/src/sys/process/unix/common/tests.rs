use super::*;
use crate::ffi::OsStr;
#[cfg(not(linux_none))]
use crate::sys::{cvt, cvt_nz};
use crate::{mem, ptr};
#[cfg(linux_none)]
use self::linux_none::{cvt, cvt_nz, libc, sigaddset, sigemptyset};

/// The libc calls these tests make, on raw syscalls (there is no libc to
/// link): libc-style return values, -1 with errno set on failure.
#[cfg(linux_none)]
mod linux_none {
    use crate::io;

    pub mod libc {
        pub use libc::*;
        use linux_none_rt::sys;

        fn ret(r: sys::SysResult) -> c_int {
            r.map_or_else(
                |e| {
                    crate::sys::io::set_errno(e);
                    -1
                },
                |v| v as c_int,
            )
        }

        pub unsafe fn kill(pid: pid_t, sig: c_int) -> c_int {
            ret(sys::kill(pid, sig as usize))
        }

        pub unsafe fn getpgid(pid: pid_t) -> pid_t {
            ret(sys::getpgid(pid))
        }

        pub unsafe fn pthread_sigmask(
            how: c_int,
            set: *const sigset_t,
            old: *mut sigset_t,
        ) -> c_int {
            // returns the error number rather than setting errno
            unsafe { sys::rt_sigprocmask(how as usize, set.cast(), old.cast()) }.err().unwrap_or(0)
        }
    }

    pub unsafe fn sigemptyset(set: *mut libc::sigset_t) -> libc::c_int {
        unsafe { set.write_bytes(0, 1) };
        0
    }

    pub unsafe fn sigaddset(set: *mut libc::sigset_t, sig: libc::c_int) -> libc::c_int {
        let bit = (sig - 1) as usize;
        unsafe { *set.cast::<u64>() |= 1 << bit };
        0
    }

    pub fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
        if r == -1 { Err(io::Error::last_os_error()) } else { Ok(r) }
    }

    pub fn cvt_nz(r: libc::c_int) -> io::Result<()> {
        if r == 0 { Ok(()) } else { Err(io::Error::from_raw_os_error(r)) }
    }
}

macro_rules! t {
    ($e:expr) => {
        match $e {
            Ok(t) => t,
            Err(e) => panic!("received error for `{}`: {}", stringify!($e), e),
        }
    };
}

#[test]
#[cfg_attr(
    any(
        // See #14232 for more information, but it appears that signal delivery to a
        // newly spawned process may just be raced in the macOS, so to prevent this
        // test from being flaky we ignore it on macOS.
        target_os = "macos",
        // cat not available
        target_os = "l4re",
        // When run under our current QEMU emulation test suite this test fails,
        // although the reason isn't very clear as to why. For now this test is
        // ignored there.
        target_arch = "arm",
        target_arch = "aarch64",
        target_arch = "riscv64",
    ),
    ignore
)]
fn test_process_mask() {
    // Test to make sure that a signal mask *does* get inherited.
    fn test_inner(mut cmd: Command) {
        unsafe {
            let mut set = mem::MaybeUninit::<libc::sigset_t>::uninit();
            let mut old_set = mem::MaybeUninit::<libc::sigset_t>::uninit();
            t!(cvt(sigemptyset(set.as_mut_ptr())));
            t!(cvt(sigaddset(set.as_mut_ptr(), libc::SIGINT)));
            t!(cvt_nz(libc::pthread_sigmask(
                libc::SIG_SETMASK,
                set.as_ptr(),
                old_set.as_mut_ptr()
            )));

            cmd.stdin(Stdio::MakePipe);
            cmd.stdout(Stdio::MakePipe);

            let (mut cat, mut pipes) = t!(cmd.spawn(Stdio::Null, true));
            let stdin_write = pipes.stdin.take().unwrap();
            let stdout_read = pipes.stdout.take().unwrap();

            t!(cvt_nz(libc::pthread_sigmask(libc::SIG_SETMASK, old_set.as_ptr(), ptr::null_mut())));

            t!(cvt(libc::kill(cat.id() as libc::pid_t, libc::SIGINT)));
            // We need to wait until SIGINT is definitely delivered. The
            // easiest way is to write something to cat, and try to read it
            // back: if SIGINT is unmasked, it'll get delivered when cat is
            // next scheduled.
            let _ = stdin_write.write(b"Hello");
            drop(stdin_write);

            // Exactly 5 bytes should be read.
            let mut buf = [0; 5];
            let ret = t!(stdout_read.read(&mut buf));
            assert_eq!(ret, 5);
            assert_eq!(&buf, b"Hello");

            t!(cat.wait());
        }
    }

    // A plain `Command::new` uses the posix_spawn path on many platforms.
    let cmd = Command::new(OsStr::new("cat"));
    test_inner(cmd);

    // Specifying `pre_exec` forces the fork/exec path.
    let mut cmd = Command::new(OsStr::new("cat"));
    unsafe { cmd.pre_exec(Box::new(|| Ok(()))) };
    test_inner(cmd);
}

#[test]
#[cfg_attr(
    any(
        // See test_process_mask
        target_os = "macos",
        // cat not available
        target_os = "l4re",
        target_arch = "arm",
        target_arch = "aarch64",
        target_arch = "riscv64",
    ),
    ignore
)]
fn test_process_group_posix_spawn() {
    unsafe {
        // Spawn a cat subprocess that's just going to hang since there is no I/O.
        let mut cmd = Command::new(OsStr::new("cat"));
        cmd.pgroup(0);
        cmd.stdin(Stdio::MakePipe);
        cmd.stdout(Stdio::MakePipe);
        let (mut cat, _pipes) = t!(cmd.spawn(Stdio::Null, true));

        let pid = cat.id() as libc::pid_t;
        let pgid = libc::getpgid(pid);
        assert_ne!(-1, pgid, "getpgid failed");
        assert_eq!(pid, pgid, "child process ID does not match its process group ID");

        // Check that we can kill its process group, which means there *is* one.
        t!(cvt(libc::kill(-pgid, libc::SIGINT)));

        t!(cat.wait());
    }
}

#[test]
#[cfg_attr(
    any(
        // See test_process_mask
        target_os = "macos",
        // cat not available
        target_os = "l4re",
        target_arch = "arm",
        target_arch = "aarch64",
        target_arch = "riscv64",
    ),
    ignore
)]
fn test_process_group_no_posix_spawn() {
    unsafe {
        // Same as above, create hang-y cat. This time, force using the non-posix_spawnp path.
        let mut cmd = Command::new(OsStr::new("cat"));
        cmd.pgroup(0);
        cmd.pre_exec(Box::new(|| Ok(()))); // pre_exec forces fork + exec
        cmd.stdin(Stdio::MakePipe);
        cmd.stdout(Stdio::MakePipe);
        let (mut cat, _pipes) = t!(cmd.spawn(Stdio::Null, true));

        let pid = cat.id() as libc::pid_t;
        let pgid = libc::getpgid(pid);
        assert_ne!(-1, pgid, "getpgid failed");
        assert_eq!(pid, pgid, "child process ID does not match its process group ID");

        if cfg!(target_os = "qnx") {
            // kill(-pgid) appears to be unable to terminate the child process on QNX8
            return;
        }

        // Check that we can kill its process group, which means there *is* one.
        t!(cvt(libc::kill(-pgid, libc::SIGINT)));

        t!(cat.wait());
    }
}

#[test]
#[cfg_attr(
    any(
        // See test_process_mask
        target_os = "macos",
        // cat not available
        target_os = "l4re",
        target_arch = "arm",
        target_arch = "aarch64",
        target_arch = "riscv64",
    ),
    ignore
)]
fn test_setsid_posix_spawn() {
    // Spawn a cat subprocess that's just going to hang since there is no I/O.
    let mut cmd = Command::new(OsStr::new("cat"));
    cmd.setsid(true);
    cmd.stdin(Stdio::MakePipe);
    cmd.stdout(Stdio::MakePipe);
    let (mut cat, _pipes) = t!(cmd.spawn(Stdio::Null, true));

    unsafe {
        let pid = cat.id() as libc::pid_t;
        let pgid = libc::getpgid(pid);
        assert_ne!(-1, pgid, "getpgid failed");
        assert_eq!(pid, pgid, "child process ID does not match its process group ID");

        if cfg!(target_os = "qnx") {
            // kill(-pgid) appears to be unable to terminate the child process on QNX8
            return;
        }

        // Setsid will create a new session and process group, so check that
        // we can kill the process group, which means there *is* one.
        t!(cvt(libc::kill(-pgid, libc::SIGINT)));

        t!(cat.wait());
    }
}

#[test]
#[cfg_attr(
    any(
        // See test_process_mask
        target_os = "macos",
        // cat not available
        target_os = "l4re",
        target_arch = "arm",
        target_arch = "aarch64",
        target_arch = "riscv64",
    ),
    ignore
)]
fn test_setsid_no_posix_spawn() {
    let mut cmd = Command::new(OsStr::new("cat"));
    cmd.setsid(true);
    cmd.stdin(Stdio::MakePipe);
    cmd.stdout(Stdio::MakePipe);

    unsafe {
        // Same as above, create hang-y cat. This time, force using the non-posix_spawn path.
        cmd.pre_exec(Box::new(|| Ok(()))); // pre_exec forces fork + exec rather than posix spawn.
        let (mut cat, _pipes) = t!(cmd.spawn(Stdio::Null, true));

        let pid = cat.id() as libc::pid_t;
        let pgid = libc::getpgid(pid);
        assert_ne!(-1, pgid, "getpgid failed");
        assert_eq!(pid, pgid, "child process ID does not match its process group ID");

        if cfg!(target_os = "qnx") {
            // kill(-pgid) appears to be unable to terminate the child process on QNX8
            return;
        }

        // Setsid will create a new session and process group, so check that
        // we can kill the process group, which means there *is* one.
        t!(cvt(libc::kill(-pgid, libc::SIGINT)));

        t!(cat.wait());
    }
}

#[test]
fn test_program_kind() {
    let vectors = &[
        ("foo", ProgramKind::PathLookup),
        ("foo.out", ProgramKind::PathLookup),
        ("./foo", ProgramKind::Relative),
        ("../foo", ProgramKind::Relative),
        ("dir/foo", ProgramKind::Relative),
        // Note that paths on Unix can't contain / in them, so this is actually the directory "fo\\"
        // followed by the file "o".
        ("fo\\/o", ProgramKind::Relative),
        ("/foo", ProgramKind::Absolute),
        ("/dir/../foo", ProgramKind::Absolute),
    ];

    for (program, expected_kind) in vectors {
        assert_eq!(
            ProgramKind::new(program.as_ref()),
            *expected_kind,
            "actual != expected program kind for input {program}",
        );
    }
}

// Test that Rust std handles wait status values (`ExitStatus`) the way that Unix does,
// at least for the values which represent a Unix exit status (`ExitCode`).
// Should work on every #[cfg(unix)] platform.  However:
#[cfg(not(any(
    // Fuchsia is not Unix and has totally broken std::os::unix.
    // https://github.com/rust-lang/rust/issues/58590#issuecomment-836535609
    target_os = "fuchsia",
)))]
#[test]
fn unix_exit_statuses() {
    use crate::num::NonZero;
    use crate::os::unix::process::ExitStatusExt;
    use crate::process::*;

    for exit_code in 0..=0xff {
        // FIXME impl From<ExitCode> for ExitStatus and then test that here too;
        // the two ExitStatus values should be the same
        let raw_wait_status = exit_code << 8;
        let exit_status = ExitStatus::from_raw(raw_wait_status);

        assert_eq!(exit_status.code(), Some(exit_code));

        if let Ok(nz) = NonZero::try_from(exit_code) {
            assert!(!exit_status.success());
            let es_error = exit_status.exit_ok().unwrap_err();
            assert_eq!(es_error.code().unwrap(), i32::from(nz));
        } else {
            assert!(exit_status.success());
            assert_eq!(exit_status.exit_ok(), Ok(()));
        }
    }
}
