//! DNS for `getaddrinfo`: `linux_none_rt::dns` with the configuration in
//! `/etc/resolv.conf` and query ids from the system's random source.

use linux_none_rt::dns::{self, Config, Error, Family};

use super::netc::{AF_INET, AF_INET6, EAI_AGAIN, EAI_FAIL, EAI_NONAME, EAI_SYSTEM, c_int};
use crate::net::{IpAddr, Ipv4Addr};

/// Addresses kept from one answer, as musl does.
const MAXADDRS: usize = 48;

/// `host`'s addresses of `family` (`AF_UNSPEC`, `AF_INET` or `AF_INET6`),
/// or the `EAI_*` code (with errno set for `EAI_SYSTEM`).
pub fn lookup(host: &[u8], family: c_int) -> Result<Vec<IpAddr>, c_int> {
    let family = match family {
        AF_INET => Family::V4,
        AF_INET6 => Family::V6,
        _ => Family::Any,
    };
    // a missing file means the defaults: ask 127.0.0.1
    let conf = Config::parse(&crate::fs::read("/etc/resolv.conf").unwrap_or_default());
    let mut random = || {
        let mut id = [0; 2];
        crate::sys::random::fill_bytes(&mut id);
        u16::from_ne_bytes(id)
    };
    let mut buf = vec![0u8; 65535];
    let mut out = [IpAddr::V4(Ipv4Addr::UNSPECIFIED); MAXADDRS];
    match dns::lookup(&conf, host, family, &mut random, &mut buf, &mut out) {
        Ok(n) => Ok(out[..n].to_vec()),
        Err(Error::NoName) => Err(EAI_NONAME),
        Err(Error::Again) => Err(EAI_AGAIN),
        Err(Error::Fail) => Err(EAI_FAIL),
        Err(Error::Sys(e)) => {
            crate::sys::io::set_errno(e);
            Err(EAI_SYSTEM)
        }
    }
}
