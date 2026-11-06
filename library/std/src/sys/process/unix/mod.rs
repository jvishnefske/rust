#[cfg_attr(
    any(target_os = "espidf", target_os = "horizon", target_os = "nuttx", target_os = "l4re"),
    allow(unused)
)]
mod common;

cfg_select! {
    target_os = "fuchsia" => {
        mod fuchsia;
        use fuchsia as imp;
    }
    target_os = "vxworks" => {
        mod vxworks;
        use vxworks as imp;
    }
    any(
        target_os = "espidf",
        target_os = "horizon",
        target_os = "vita",
        target_os = "nuttx",
        target_os = "l4re"
    ) => {
        mod unsupported;
        use unsupported as imp;
        pub use unsupported::output;
    }
    linux_none => {
        mod linux_none;
        use linux_none as imp;
    }
    _ => {
        mod unix;
        use unix as imp;
    }
}

#[cfg(all(target_os = "linux", not(linux_none)))]
mod pidfd;

pub use imp::{ExitStatus, ExitStatusError, Process};
#[cfg(linux_none)]
pub use linux_none::PidFd;
#[cfg(all(target_os = "linux", not(linux_none)))]
pub use pidfd::PidFd;

pub use self::common::{
    ChildPipe, Command, CommandArgs, ExitCode, Stdio, getpid, getppid, read_output,
};
pub use crate::ffi::OsString as EnvKey;
