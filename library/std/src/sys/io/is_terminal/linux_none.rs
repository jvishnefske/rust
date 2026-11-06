use crate::os::fd::{AsFd, AsRawFd};

pub fn is_terminal(fd: &impl AsFd) -> bool {
    // isatty(3): a terminal is what answers TCGETS
    const TCGETS: usize = 0x5401;
    let mut termios = [0u8; 64];
    let fd = fd.as_fd().as_raw_fd();
    unsafe { linux_none_rt::sys::ioctl(fd, TCGETS, termios.as_mut_ptr() as usize) }.is_ok()
}
