use crate::ffi::OsString;
use crate::io;
use crate::os::unix::ffi::OsStringExt;

/// The node name from `uname(2)`, which is what `gethostname` returns.
pub fn hostname() -> io::Result<OsString> {
    let mut uts: libc::utsname = unsafe { crate::mem::zeroed() };
    crate::sys::cvt(unsafe { linux_none_rt::sys::uname((&raw mut uts).cast()) })?;
    let name = &uts.nodename;
    let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    Ok(OsString::from_vec(name[..len].iter().map(|&c| c as u8).collect()))
}
