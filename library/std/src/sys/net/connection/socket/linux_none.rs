//! Sockets on linux-none.
//!
//! The generic socket code (`socket/mod.rs`) and `os::unix::net` call the
//! platform through `netc`, which elsewhere is libc. Here `netc` is libc's
//! types and constants plus [`netc`]'s own functions, with libc's signatures
//! and conventions (`-1` and errno on failure), on `linux_none_rt` syscalls.
//! Host name lookup knows numeric addresses and `/etc/hosts`, then asks the
//! DNS servers in `/etc/resolv.conf` (`linux_none_rt::dns`).

#![allow(dead_code)]

use libc::{MSG_PEEK, c_int, c_void, sockaddr, socklen_t};

use crate::io::{self, BorrowedBuf, BorrowedCursor, IoSlice, IoSliceMut};
use crate::net::{Shutdown, SocketAddr};
use crate::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, RawFd};
use crate::sys::fd::FileDesc;
use crate::sys::net::{getsockopt, setsockopt};
use crate::sys::{AsInner, FromInner, IntoInner};
use crate::time::{Duration, Instant};
use crate::{cmp, mem};

use super::socket_addr_to_c;

#[expect(non_camel_case_types)]
pub type wrlen_t = libc::size_t;

mod dns;

/// libc's interface to sockets, on raw syscalls.
pub(crate) mod netc {
    #![allow(non_camel_case_types)]

    use linux_none_rt::sys;
    // types and constants (functions not defined below would come from libc,
    // which the link check rejects)
    pub use libc::*;

    use crate::sys::io::set_errno;

    fn ret(r: Result<usize, i32>) -> isize {
        match r {
            Ok(v) => v as isize,
            Err(e) => {
                set_errno(e);
                -1
            }
        }
    }

    pub unsafe fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int {
        ret(sys::socket(domain as u16, ty as u32, protocol as u32).map(|f| f as usize)) as c_int
    }
    pub unsafe fn socketpair(domain: c_int, ty: c_int, protocol: c_int, sv: *mut c_int) -> c_int {
        ret(unsafe { sys::socketpair(domain as u16, ty as u32, protocol as u32, sv.cast()) }) as c_int
    }
    pub unsafe fn connect(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
        ret(unsafe { sys::connect(fd, addr.cast(), len) }) as c_int
    }
    pub unsafe fn bind(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
        ret(unsafe { sys::bind(fd, addr.cast(), len) }) as c_int
    }
    pub unsafe fn listen(fd: c_int, backlog: c_int) -> c_int {
        ret(sys::listen(fd, backlog)) as c_int
    }
    pub unsafe fn accept4(fd: c_int, addr: *mut sockaddr, len: *mut socklen_t, flags: c_int) -> c_int {
        ret(unsafe { sys::accept4(fd, addr.cast(), len, flags as u32) }.map(|f| f as usize)) as c_int
    }
    pub unsafe fn send(fd: c_int, buf: *const c_void, len: size_t, flags: c_int) -> ssize_t {
        unsafe { sendto(fd, buf, len, flags, crate::ptr::null(), 0) }
    }
    pub unsafe fn sendto(
        fd: c_int,
        buf: *const c_void,
        len: size_t,
        flags: c_int,
        addr: *const sockaddr,
        alen: socklen_t,
    ) -> ssize_t {
        ret(unsafe { sys::sendto(fd, buf.cast(), len, flags as u32, addr.cast(), alen) })
    }
    pub unsafe fn recv(fd: c_int, buf: *mut c_void, len: size_t, flags: c_int) -> ssize_t {
        unsafe { recvfrom(fd, buf, len, flags, crate::ptr::null_mut(), crate::ptr::null_mut()) }
    }
    pub unsafe fn recvfrom(
        fd: c_int,
        buf: *mut c_void,
        len: size_t,
        flags: c_int,
        addr: *mut sockaddr,
        alen: *mut socklen_t,
    ) -> ssize_t {
        ret(unsafe { sys::recvfrom(fd, buf.cast(), len, flags as u32, addr.cast(), alen) })
    }
    pub unsafe fn sendmsg(fd: c_int, msg: *const msghdr, flags: c_int) -> ssize_t {
        ret(unsafe { sys::sendmsg(fd, msg.cast(), flags as u32) })
    }
    pub unsafe fn recvmsg(fd: c_int, msg: *mut msghdr, flags: c_int) -> ssize_t {
        ret(unsafe { sys::recvmsg(fd, msg.cast(), flags as u32) })
    }
    pub unsafe fn shutdown(fd: c_int, how: c_int) -> c_int {
        ret(sys::shutdown(fd, how as u32)) as c_int
    }
    pub unsafe fn setsockopt(
        fd: c_int,
        level: c_int,
        name: c_int,
        val: *const c_void,
        len: socklen_t,
    ) -> c_int {
        ret(unsafe { sys::setsockopt(fd, level as u32, name as u32, val.cast(), len) }) as c_int
    }
    pub unsafe fn getsockopt(
        fd: c_int,
        level: c_int,
        name: c_int,
        val: *mut c_void,
        len: *mut socklen_t,
    ) -> c_int {
        ret(unsafe { sys::getsockopt(fd, level as u32, name as u32, val.cast(), len) }) as c_int
    }
    pub unsafe fn getsockname(fd: c_int, addr: *mut sockaddr, len: *mut socklen_t) -> c_int {
        ret(unsafe { sys::getsockname(fd, addr.cast(), len) }) as c_int
    }
    pub unsafe fn getpeername(fd: c_int, addr: *mut sockaddr, len: *mut socklen_t) -> c_int {
        ret(unsafe { sys::getpeername(fd, addr.cast(), len) }) as c_int
    }
    pub unsafe fn poll(fds: *mut pollfd, n: nfds_t, timeout_ms: c_int) -> c_int {
        let ts = (timeout_ms >= 0).then(|| sys::Timespec {
            sec: (timeout_ms / 1000) as i64,
            nsec: (timeout_ms % 1000) as i64 * 1_000_000,
        });
        let tsp = ts.as_ref().map_or(crate::ptr::null(), |t| t as *const sys::Timespec);
        ret(unsafe { sys::ppoll(fds.cast(), n as usize, tsp) }) as c_int
    }

    /// One `addrinfo` with the address it points to.
    #[repr(C)]
    struct Node {
        ai: addrinfo,
        addr: sockaddr_storage,
    }

    /// `getaddrinfo` for a numeric address, a name in `/etc/hosts`
    /// (`localhost` resolves even without one) or else in DNS. Only `node`,
    /// `hints.ai_family` and `hints.ai_socktype` are looked at.
    pub unsafe fn getaddrinfo(
        node: *const c_char,
        _service: *const c_char,
        hints: *const addrinfo,
        res: *mut *mut addrinfo,
    ) -> c_int {
        use crate::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        let host = unsafe { crate::ffi::CStr::from_ptr(node) }.to_bytes();
        let socktype = unsafe { hints.as_ref() }.map_or(0, |h| h.ai_socktype);
        let family = unsafe { hints.as_ref() }.map_or(AF_UNSPEC, |h| h.ai_family);
        let numeric = crate::str::from_utf8(host).ok().and_then(|h| h.parse::<IpAddr>().ok());
        let mut addrs: Vec<IpAddr> = match numeric {
            Some(a) => vec![a],
            None => hosts_file(host),
        };
        if addrs.is_empty() && host.eq_ignore_ascii_case(b"localhost") {
            addrs = vec![IpAddr::V4(Ipv4Addr::LOCALHOST), IpAddr::V6(Ipv6Addr::LOCALHOST)];
        }
        addrs.retain(|a| family == AF_UNSPEC || (family == AF_INET) == a.is_ipv4());
        if addrs.is_empty() && numeric.is_none() {
            addrs = match super::dns::lookup(host, family) {
                Ok(addrs) => addrs,
                Err(e) => return e,
            };
        }
        if addrs.is_empty() {
            return EAI_NONAME;
        }
        let mut head: *mut addrinfo = crate::ptr::null_mut();
        for ip in addrs.into_iter().rev() {
            let (repr, len) = super::super::socket_addr_to_c(&crate::net::SocketAddr::new(ip, 0));
            let mut node: Box<Node> = Box::new(unsafe { crate::mem::zeroed() });
            unsafe {
                crate::ptr::copy_nonoverlapping(
                    repr.as_ptr().cast::<u8>(),
                    (&raw mut node.addr).cast::<u8>(),
                    len as usize,
                )
            };
            node.ai.ai_family = if ip.is_ipv4() { AF_INET } else { AF_INET6 };
            node.ai.ai_socktype = socktype;
            node.ai.ai_addrlen = len;
            node.ai.ai_next = head;
            let node = Box::into_raw(node);
            unsafe { (*node).ai.ai_addr = (&raw mut (*node).addr).cast() };
            head = node.cast();
        }
        unsafe { *res = head };
        0
    }

    /// The addresses `/etc/hosts` gives `name`, in file order.
    fn hosts_file(name: &[u8]) -> Vec<crate::net::IpAddr> {
        let Ok(hosts) = crate::fs::read("/etc/hosts") else { return Vec::new() };
        let mut out = Vec::new();
        for line in hosts.split(|&b| b == b'\n') {
            let line = line.split(|&b| b == b'#').next().unwrap_or(&[]);
            let mut fields = line.split(|b| b.is_ascii_whitespace()).filter(|f| !f.is_empty());
            let Some(addr) = fields.next() else { continue };
            if fields.any(|n| n.eq_ignore_ascii_case(name))
                && let Some(a) = crate::str::from_utf8(addr).ok().and_then(|a| a.parse().ok())
                && !out.contains(&a)
            {
                out.push(a);
            }
        }
        out
    }

    pub unsafe fn freeaddrinfo(mut ai: *mut addrinfo) {
        while !ai.is_null() {
            let node = unsafe { Box::from_raw(ai.cast::<Node>()) };
            ai = node.ai.ai_next;
        }
    }

    pub fn gai_strerror(err: c_int) -> &'static str {
        match err {
            EAI_NONAME => "Name does not resolve",
            EAI_AGAIN => "Temporary failure in name resolution",
            EAI_FAIL => "Non-recoverable failure in name resolution",
            EAI_SYSTEM => "System error",
            _ => "Unknown error",
        }
    }
}

/// Converts the `-1` and errno of a [`netc`] call to an `io::Error`.
pub fn cvt<T: IsMinusOne>(t: T) -> io::Result<T> {
    if t.is_minus_one() { Err(io::Error::last_os_error()) } else { Ok(t) }
}

/// [`cvt`], retrying on `EINTR`.
pub fn cvt_r<T, F>(mut f: F) -> io::Result<T>
where
    T: IsMinusOne,
    F: FnMut() -> T,
{
    loop {
        match cvt(f()) {
            Err(ref e) if e.is_interrupted() => {}
            other => return other,
        }
    }
}

#[doc(hidden)]
pub trait IsMinusOne {
    fn is_minus_one(&self) -> bool;
}

macro_rules! impl_is_minus_one {
    ($($t:ident)*) => ($(impl IsMinusOne for $t {
        fn is_minus_one(&self) -> bool {
            *self == -1
        }
    })*)
}

impl_is_minus_one! { i8 i16 i32 i64 isize }

pub struct Socket(FileDesc);

pub fn init() {}

pub fn cvt_gai(err: c_int) -> io::Result<()> {
    if err == 0 {
        return Ok(());
    }
    if err == netc::EAI_SYSTEM {
        return Err(io::Error::last_os_error());
    }
    let detail = netc::gai_strerror(err);
    Err(io::Error::new(
        io::ErrorKind::Uncategorized,
        &format!("failed to lookup address information: {detail}")[..],
    ))
}

impl Socket {
    pub fn new(family: c_int, ty: c_int) -> io::Result<Socket> {
        let fd = cvt(unsafe { netc::socket(family, ty | libc::SOCK_CLOEXEC, 0) })?;
        Ok(Socket(unsafe { FileDesc::from_raw_fd(fd) }))
    }

    pub fn new_pair(fam: c_int, ty: c_int) -> io::Result<(Socket, Socket)> {
        unsafe {
            let mut fds = [0, 0];
            cvt(netc::socketpair(fam, ty | libc::SOCK_CLOEXEC, 0, fds.as_mut_ptr()))?;
            Ok((Socket(FileDesc::from_raw_fd(fds[0])), Socket(FileDesc::from_raw_fd(fds[1]))))
        }
    }

    pub fn connect(&self, addr: &SocketAddr) -> io::Result<()> {
        let (addr, len) = socket_addr_to_c(addr);
        loop {
            let result = unsafe { netc::connect(self.as_raw_fd(), addr.as_ptr(), len) };
            if result.is_minus_one() {
                let err = crate::sys::io::errno();
                match err {
                    libc::EINTR => continue,
                    libc::EISCONN => return Ok(()),
                    _ => return Err(io::Error::from_raw_os_error(err)),
                }
            }
            return Ok(());
        }
    }

    pub fn connect_timeout(&self, addr: &SocketAddr, timeout: Duration) -> io::Result<()> {
        self.set_nonblocking(true)?;
        let r = unsafe {
            let (addr, len) = socket_addr_to_c(addr);
            cvt(netc::connect(self.as_raw_fd(), addr.as_ptr(), len))
        };
        self.set_nonblocking(false)?;

        match r {
            Ok(_) => return Ok(()),
            Err(ref e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
            Err(e) => return Err(e),
        }

        let mut pollfd = libc::pollfd { fd: self.as_raw_fd(), events: libc::POLLOUT, revents: 0 };

        if timeout.as_secs() == 0 && timeout.subsec_nanos() == 0 {
            return Err(io::Error::ZERO_TIMEOUT);
        }

        let start = Instant::now();

        loop {
            let elapsed = start.elapsed();
            if elapsed >= timeout {
                return Err(io::const_error!(io::ErrorKind::TimedOut, "connection timed out"));
            }

            let timeout = timeout - elapsed;
            let mut timeout = timeout
                .as_secs()
                .saturating_mul(1_000)
                .saturating_add(timeout.subsec_nanos() as u64 / 1_000_000);
            if timeout == 0 {
                timeout = 1;
            }

            let timeout = cmp::min(timeout, c_int::MAX as u64) as c_int;

            match unsafe { netc::poll(&mut pollfd, 1, timeout) } {
                -1 => {
                    let err = io::Error::last_os_error();
                    if !err.is_interrupted() {
                        return Err(err);
                    }
                }
                0 => {}
                _ => {
                    if pollfd.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                        let e = self.take_error()?.unwrap_or_else(|| {
                            io::const_error!(
                                io::ErrorKind::Uncategorized,
                                "no error set after POLLHUP",
                            )
                        });
                        return Err(e);
                    }

                    return Ok(());
                }
            }
        }
    }

    pub fn accept(&self, storage: *mut sockaddr, len: *mut socklen_t) -> io::Result<Socket> {
        unsafe {
            let fd = cvt_r(|| netc::accept4(self.as_raw_fd(), storage, len, libc::SOCK_CLOEXEC))?;
            Ok(Socket(FileDesc::from_raw_fd(fd)))
        }
    }

    pub fn duplicate(&self) -> io::Result<Socket> {
        self.0.duplicate().map(Socket)
    }

    pub fn send_with_flags(&self, buf: &[u8], flags: c_int) -> io::Result<usize> {
        let len = cmp::min(buf.len(), super::MAX_SEND_LEN) as wrlen_t;
        let ret = cvt(unsafe {
            netc::send(self.as_raw_fd(), buf.as_ptr() as *const c_void, len, flags)
        })?;
        Ok(ret as usize)
    }

    fn recv_with_flags(&self, mut buf: BorrowedCursor<'_, u8>, flags: c_int) -> io::Result<()> {
        let ret = cvt(unsafe {
            netc::recv(
                self.as_raw_fd(),
                buf.as_mut().as_mut_ptr() as *mut c_void,
                buf.capacity(),
                flags,
            )
        })?;
        unsafe {
            buf.advance(ret as usize);
        }
        Ok(())
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut buf = BorrowedBuf::from(buf);
        self.recv_with_flags(buf.unfilled(), 0)?;
        Ok(buf.len())
    }

    pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut buf = BorrowedBuf::from(buf);
        self.recv_with_flags(buf.unfilled(), MSG_PEEK)?;
        Ok(buf.len())
    }

    pub fn read_buf(&self, buf: BorrowedCursor<'_, u8>) -> io::Result<()> {
        self.recv_with_flags(buf, 0)
    }

    pub fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        self.0.read_vectored(bufs)
    }

    #[inline]
    pub fn is_read_vectored(&self) -> bool {
        self.0.is_read_vectored()
    }

    fn recv_from_with_flags(
        &self,
        buf: &mut [u8],
        flags: c_int,
    ) -> io::Result<(usize, SocketAddr)> {
        let mut storage: mem::MaybeUninit<libc::sockaddr_storage> = mem::MaybeUninit::uninit();
        let mut addrlen = size_of_val(&storage) as libc::socklen_t;

        let n = cvt(unsafe {
            netc::recvfrom(
                self.as_raw_fd(),
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                flags,
                (&raw mut storage) as *mut _,
                &mut addrlen,
            )
        })?;
        Ok((n as usize, unsafe { super::socket_addr_from_c(storage.as_ptr(), addrlen as usize)? }))
    }

    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv_from_with_flags(buf, 0)
    }

    pub fn recv_msg(&self, msg: &mut libc::msghdr) -> io::Result<usize> {
        let n = cvt(unsafe { netc::recvmsg(self.as_raw_fd(), msg, libc::MSG_CMSG_CLOEXEC) })?;
        Ok(n as usize)
    }

    pub fn peek_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv_from_with_flags(buf, MSG_PEEK)
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    pub fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.0.write_vectored(bufs)
    }

    #[inline]
    pub fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }

    pub fn send_msg(&self, msg: &mut libc::msghdr) -> io::Result<usize> {
        let n = cvt(unsafe { netc::sendmsg(self.as_raw_fd(), msg, 0) })?;
        Ok(n as usize)
    }

    pub fn set_timeout(&self, dur: Option<Duration>, kind: libc::c_int) -> io::Result<()> {
        let timeout = match dur {
            Some(dur) => {
                if dur.as_secs() == 0 && dur.subsec_nanos() == 0 {
                    return Err(io::Error::ZERO_TIMEOUT);
                }

                let secs = if dur.as_secs() > libc::time_t::MAX as u64 {
                    libc::time_t::MAX
                } else {
                    dur.as_secs() as libc::time_t
                };
                let mut timeout = libc::timeval { tv_sec: secs, tv_usec: dur.subsec_micros() as _ };
                if timeout.tv_sec == 0 && timeout.tv_usec == 0 {
                    timeout.tv_usec = 1;
                }
                timeout
            }
            None => libc::timeval { tv_sec: 0, tv_usec: 0 },
        };
        unsafe { setsockopt(self, libc::SOL_SOCKET, kind, timeout) }
    }

    pub fn timeout(&self, kind: libc::c_int) -> io::Result<Option<Duration>> {
        let raw: libc::timeval = unsafe { getsockopt(self, libc::SOL_SOCKET, kind)? };
        if raw.tv_sec == 0 && raw.tv_usec == 0 {
            Ok(None)
        } else {
            let sec = raw.tv_sec as u64;
            let nsec = (raw.tv_usec as u32) * 1000;
            Ok(Some(Duration::new(sec, nsec)))
        }
    }

    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        let how = match how {
            Shutdown::Write => libc::SHUT_WR,
            Shutdown::Read => libc::SHUT_RD,
            Shutdown::Both => libc::SHUT_RDWR,
        };
        cvt(unsafe { netc::shutdown(self.as_raw_fd(), how) })?;
        Ok(())
    }

    pub fn set_linger(&self, linger: Option<Duration>) -> io::Result<()> {
        let linger = libc::linger {
            l_onoff: linger.is_some() as c_int,
            l_linger: cmp::min(linger.unwrap_or_default().as_secs(), c_int::MAX as u64) as c_int,
        };

        unsafe { setsockopt(self, libc::SOL_SOCKET, libc::SO_LINGER, linger) }
    }

    pub fn linger(&self) -> io::Result<Option<Duration>> {
        let val: libc::linger = unsafe { getsockopt(self, libc::SOL_SOCKET, libc::SO_LINGER)? };

        Ok((val.l_onoff != 0).then(|| Duration::from_secs(val.l_linger as u64)))
    }

    pub fn set_keepalive(&self, keepalive: bool) -> io::Result<()> {
        unsafe { setsockopt(self, libc::SOL_SOCKET, libc::SO_KEEPALIVE, keepalive as c_int) }
    }

    pub fn keepalive(&self) -> io::Result<bool> {
        let raw: c_int = unsafe { getsockopt(self, libc::SOL_SOCKET, libc::SO_KEEPALIVE)? };
        Ok(raw != 0)
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        unsafe { setsockopt(self, libc::IPPROTO_TCP, libc::TCP_NODELAY, nodelay as c_int) }
    }

    pub fn nodelay(&self) -> io::Result<bool> {
        let raw: c_int = unsafe { getsockopt(self, libc::IPPROTO_TCP, libc::TCP_NODELAY)? };
        Ok(raw != 0)
    }

    pub fn set_quickack(&self, quickack: bool) -> io::Result<()> {
        unsafe { setsockopt(self, libc::IPPROTO_TCP, libc::TCP_QUICKACK, quickack as c_int) }
    }

    pub fn quickack(&self) -> io::Result<bool> {
        let raw: c_int = unsafe { getsockopt(self, libc::IPPROTO_TCP, libc::TCP_QUICKACK)? };
        Ok(raw != 0)
    }

    pub fn set_deferaccept(&self, accept: Duration) -> io::Result<()> {
        let val = cmp::min(accept.as_secs(), c_int::MAX as u64) as c_int;
        unsafe { setsockopt(self, libc::IPPROTO_TCP, libc::TCP_DEFER_ACCEPT, val) }
    }

    pub fn deferaccept(&self) -> io::Result<Duration> {
        let raw: c_int = unsafe { getsockopt(self, libc::IPPROTO_TCP, libc::TCP_DEFER_ACCEPT)? };
        Ok(Duration::from_secs(raw as _))
    }

    pub fn set_passcred(&self, passcred: bool) -> io::Result<()> {
        unsafe { setsockopt(self, libc::SOL_SOCKET, libc::SO_PASSCRED, passcred as libc::c_int) }
    }

    pub fn passcred(&self) -> io::Result<bool> {
        let passcred: libc::c_int =
            unsafe { getsockopt(self, libc::SOL_SOCKET, libc::SO_PASSCRED)? };
        Ok(passcred != 0)
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.0.set_nonblocking(nonblocking)
    }

    pub fn set_mark(&self, mark: u32) -> io::Result<()> {
        unsafe { setsockopt(self, libc::SOL_SOCKET, libc::SO_MARK, mark as libc::c_int) }
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        let raw: c_int = unsafe { getsockopt(self, libc::SOL_SOCKET, libc::SO_ERROR)? };
        if raw == 0 { Ok(None) } else { Ok(Some(io::Error::from_raw_os_error(raw as i32))) }
    }

    pub fn as_raw(&self) -> RawFd {
        self.as_raw_fd()
    }
}

impl AsInner<FileDesc> for Socket {
    #[inline]
    fn as_inner(&self) -> &FileDesc {
        &self.0
    }
}

impl IntoInner<FileDesc> for Socket {
    fn into_inner(self) -> FileDesc {
        self.0
    }
}

impl FromInner<FileDesc> for Socket {
    fn from_inner(file_desc: FileDesc) -> Self {
        Self(file_desc)
    }
}

impl AsFd for Socket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl AsRawFd for Socket {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl IntoRawFd for Socket {
    fn into_raw_fd(self) -> RawFd {
        self.0.into_raw_fd()
    }
}

impl FromRawFd for Socket {
    unsafe fn from_raw_fd(raw_fd: RawFd) -> Self {
        Self(FromRawFd::from_raw_fd(raw_fd))
    }
}
